mod tls;

use crate::{
    config::PeerConfig,
    tunnel::{OpenTunnel, Tunnel, transport::OwnedIo, upstream::Forwarding},
};
use anytls_protocol::{
    BoxTransport, Client, DEFAULT_MAX_SESSION_AGE, DEFAULT_SCHEME, Dialer, PaddingFactory, Session,
    StreamIo, read_auth, write_auth,
};
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    runtime::Handle,
    sync::{RwLock, Semaphore},
    time::{Instant, timeout_at},
};

pub type SendHalf = tokio::io::WriteHalf<BoxTransport>;
pub type RecvHalf = tokio::io::ReadHalf<BoxTransport>;
const MAX_SESSIONS: usize = 64;

struct ClientOwner {
    client: Arc<Client>,
    runtime: Handle,
}

impl Drop for ClientOwner {
    fn drop(&mut self) {
        let client = self.client.clone();
        self.runtime.spawn(async move {
            let _ = client.shutdown().await;
        });
    }
}

#[derive(Clone)]
pub struct Connector {
    owner: Arc<ClientOwner>,
}

impl Connector {
    pub fn new(config: &PeerConfig) -> io::Result<Self> {
        config.validate()?;
        let anytls = config.anytls.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "anytls.password is required")
        })?;
        let connector = tls::client(&config.server_cert, &config.private_key)?;
        let address = config.server_addr;
        let name = ServerName::try_from(config.server_name.clone()).map_err(io::Error::other)?;
        let password = anytls.password.clone();
        let padding = Arc::new(RwLock::new(
            PaddingFactory::new(DEFAULT_SCHEME).expect("built-in AnyTLS padding scheme"),
        ));
        let auth_padding = padding.clone();
        let slots = Arc::new(Semaphore::new(MAX_SESSIONS));
        let dialer: Dialer = Arc::new(move || {
            let connector = connector.clone();
            let name = name.clone();
            let password = password.clone();
            let padding = auth_padding.clone();
            let slots = slots.clone();
            Box::pin(async move {
                let permit = slots.try_acquire_owned().map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "AnyTLS session capacity reached")
                })?;
                let tcp = TcpStream::connect(address).await?;
                tcp.set_nodelay(true)?;
                let mut stream = connector.connect(name, tcp).await?;
                check_alpn(stream.get_ref().1.alpn_protocol())?;
                let padding = padding.read().await.clone();
                write_auth(&mut stream, &password, &padding).await?;
                Ok(Box::new(OwnedIo {
                    stream,
                    _owner: permit,
                }) as BoxTransport)
            })
        });
        Ok(Self {
            owner: Arc::new(ClientOwner {
                client: Client::new(
                    dialer,
                    padding,
                    Duration::from_secs(30),
                    DEFAULT_MAX_SESSION_AGE,
                ),
                runtime: Handle::current(),
            }),
        })
    }
}

#[async_trait]
impl OpenTunnel for Connector {
    type S = SendHalf;
    type R = RecvHalf;

    async fn open_tunnel(&mut self) -> io::Result<Tunnel<Self::S, Self::R>> {
        let stream = StreamIo::new(self.owner.client.create_stream().await?);
        let stream: BoxTransport = Box::new(OwnedIo {
            stream,
            _owner: self.owner.clone(),
        });
        let (reader, writer) = tokio::io::split(stream);
        Ok(Tunnel::new(writer, reader))
    }
}

pub(crate) use tls::ALPN;

pub(crate) struct Server {
    password: String,
    slots: Arc<Semaphore>,
    sequence: AtomicUsize,
}

impl Server {
    pub(crate) fn new(password: String) -> Self {
        Self {
            password,
            slots: Arc::new(Semaphore::new(MAX_SESSIONS)),
            sequence: AtomicUsize::new(0),
        }
    }

    pub(crate) async fn accept(
        &self,
        mut stream: tokio_rustls::server::TlsStream<TcpStream>,
        deadline: Instant,
        route: Forwarding,
    ) -> io::Result<()> {
        check_alpn(stream.get_ref().1.alpn_protocol())?;
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "AnyTLS session capacity reached")
        })?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AnyTLS admission timed out",
            ));
        }
        timeout_at(deadline, read_auth(&mut stream, &self.password))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS admission timed out"))??;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AnyTLS admission timed out",
            ));
        }
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        server_session(
            OwnedIo {
                stream,
                _owner: permit,
            },
            sequence,
            route,
        )
        .await
    }
}

fn check_alpn(protocol: Option<&[u8]>) -> io::Result<()> {
    if protocol == Some(tls::ALPN) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AnyTLS ALPN mismatch",
        ))
    }
}

struct ServerSessionOwner {
    session: Option<Arc<Session>>,
    runtime: Handle,
}

impl Drop for ServerSessionOwner {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            self.runtime.spawn(async move {
                let _ = session.shutdown().await;
            });
        }
    }
}

async fn server_session(
    transport: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    sequence: usize,
    route: Forwarding,
) -> io::Result<()> {
    let padding = Arc::new(RwLock::new(
        PaddingFactory::new(DEFAULT_SCHEME).expect("built-in AnyTLS padding scheme"),
    ));
    let session = Session::new_server(
        sequence,
        Box::new(transport),
        padding,
        DEFAULT_MAX_SESSION_AGE,
    );
    let mut owner = ServerSessionOwner {
        session: Some(session.clone()),
        runtime: Handle::current(),
    };
    session.run().await?;
    let result = forward_streams(&session, route).await;
    session.shutdown().await?;
    owner.session.take();
    result
}

async fn forward_streams(
    session: &Arc<Session>,
    route: crate::tunnel::upstream::Forwarding,
) -> io::Result<()> {
    let mut streams = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            incoming = session.accept_stream() => {
                let stream = incoming?;
                match &route {
                    Forwarding::Direct => {
                        stream.handshake_success().await?;
                        let (reader, writer) = tokio::io::split(StreamIo::new(stream));
                        streams.spawn(async move {
                            if let Err(error) = crate::tunnel::server::handle_forward_tunnel(writer, reader).await {
                                log::debug!("AnyTLS forward stream ended: {error}");
                            }
                        });
                    }
                    Forwarding::Upstream(upstream) => {
                        let Ok(admission) = upstream.admit() else { continue; };
                        let upstream = upstream.clone();
                        streams.spawn(async move {
                            let result = async {
                                admission.setup(stream.handshake_success()).await?;
                                let (reader, writer) = tokio::io::split(StreamIo::new(stream));
                                crate::tunnel::server::relay(Tunnel::new(writer, reader), &upstream, admission).await
                            }.await;
                            if let Err(error) = result {
                                log::debug!("AnyTLS relay stream ended: {error}");
                            }
                        });
                    }
                }
            }
            completed = streams.join_next(), if !streams.is_empty() => {
                if let Some(Err(error)) = completed {
                    log::error!("AnyTLS forwarding task failed: {error}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

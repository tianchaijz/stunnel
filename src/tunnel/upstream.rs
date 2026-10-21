use super::OpenTunnel;
use crate::{
    config::{PeerConfig, TunnelType},
    quic, tlstcp,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
};

pub const MAX_RELAY_FLOWS: usize = 64;
pub const RELAY_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) struct RelayAdmission {
    _permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
}

impl RelayAdmission {
    pub(crate) async fn setup<T>(
        &self,
        operation: impl std::future::Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "relay setup timed out",
            ));
        }
        tokio::time::timeout_at(self.deadline, operation)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay setup timed out"))?
    }
}

#[derive(Clone, Default)]
pub enum Forwarding {
    #[default]
    Direct,
    Upstream(Arc<Upstream>),
}

impl Forwarding {
    pub fn new(peer: Option<&PeerConfig>) -> io::Result<Self> {
        peer.map(Upstream::new)
            .transpose()
            .map(|route| route.map_or(Self::Direct, |route| Self::Upstream(Arc::new(route))))
    }
}

pub struct Upstream {
    transport: Transport,
    flows: Arc<Semaphore>,
}

enum Transport {
    Tls(tlstcp::Connector),
    AnyTls(crate::anytls::Connector),
    Quinn {
        endpoint: quinn::Endpoint,
        peer: PeerConfig,
        current: Mutex<Option<Arc<QuinnGeneration>>>,
    },
    S2n {
        endpoint: Arc<s2n_quic::Client>,
        peer: PeerConfig,
        current: Mutex<Option<Arc<S2nGeneration>>>,
    },
}

struct RejectTask(tokio::task::JoinHandle<()>);
impl Drop for RejectTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct QuinnGeneration {
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    _reject: RejectTask,
}
struct S2nGeneration {
    connection: s2n_quic::connection::Handle,
    _endpoint: Arc<s2n_quic::Client>,
    closed: Arc<AtomicBool>,
    _reject: RejectTask,
}

pub(crate) trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}
pub(crate) type RelayStream = super::transport::OwnedIo<Box<dyn Duplex>, Option<Box<dyn Send>>>;

fn relay_stream(stream: impl Duplex + 'static, owner: Option<Box<dyn Send>>) -> RelayStream {
    super::transport::OwnedIo {
        stream: Box::new(stream),
        _owner: owner,
    }
}

impl Upstream {
    fn new(peer: &PeerConfig) -> io::Result<Self> {
        peer.validate()?;
        let config = quic::Config {
            addr: if peer.server_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap(),
            cert: peer.server_cert.clone(),
            priv_key: peer.private_key.clone(),
            transport: peer.quic.clone(),
        };
        let transport = match peer.tunnel_type {
            TunnelType::TlsTcp => Transport::Tls(tlstcp::client::new(&tlstcp::client::Config {
                server_addr: peer.server_addr,
                server_name: peer.server_name.clone(),
                cert: peer.server_cert.clone(),
                priv_key: peer.private_key.clone(),
            })?),
            TunnelType::AnyTls => Transport::AnyTls(crate::anytls::Connector::new(peer)?),
            TunnelType::Quinn => Transport::Quinn {
                endpoint: quic::quinn::client::new(&config)?,
                peer: peer.clone(),
                current: Mutex::new(None),
            },
            TunnelType::S2nQuic => Transport::S2n {
                endpoint: Arc::new(quic::s2n_quic::client::new(&config)?),
                peer: peer.clone(),
                current: Mutex::new(None),
            },
        };
        Ok(Self {
            transport,
            flows: Arc::new(Semaphore::new(MAX_RELAY_FLOWS)),
        })
    }

    pub(crate) fn admit(&self) -> io::Result<RelayAdmission> {
        self.flows
            .clone()
            .try_acquire_owned()
            .map(|permit| RelayAdmission {
                _permit: permit,
                deadline: tokio::time::Instant::now() + RELAY_SETUP_TIMEOUT,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "relay flow limit reached"))
    }

    pub(crate) async fn open(&self) -> io::Result<RelayStream> {
        match &self.transport {
            Transport::Tls(connector) => {
                Ok(relay_stream(connector.clone().open_tunnel().await?, None))
            }
            Transport::AnyTls(connector) => {
                Ok(relay_stream(connector.clone().open_tunnel().await?, None))
            }
            Transport::Quinn {
                endpoint,
                peer,
                current,
            } => {
                let generation = {
                    let mut current = current.lock().await;
                    if current
                        .as_ref()
                        .is_none_or(|g| g.connection.close_reason().is_some())
                    {
                        let connection = endpoint
                            .connect(peer.server_addr, &peer.server_name)
                            .map_err(io::Error::other)?
                            .await
                            .map_err(io::Error::other)?;
                        let reject = connection.clone();
                        let task = tokio::spawn(async move {
                            loop {
                                tokio::select! {
                                    stream = reject.accept_bi() => { if stream.is_err() { break; } }
                                    stream = reject.accept_uni() => { if stream.is_err() { break; } }
                                }
                            }
                        });
                        *current = Some(Arc::new(QuinnGeneration {
                            connection,
                            _endpoint: endpoint.clone(),
                            _reject: RejectTask(task),
                        }));
                    }
                    current.as_ref().unwrap().clone()
                };
                let tunnel = generation.connection.clone().open_tunnel().await?;
                Ok(relay_stream(tunnel, Some(Box::new(generation))))
            }
            Transport::S2n {
                endpoint,
                peer,
                current,
            } => {
                let generation = {
                    let mut current = current.lock().await;
                    if current
                        .as_ref()
                        .is_none_or(|g| g.closed.load(Ordering::Acquire))
                    {
                        let connect = s2n_quic::client::Connect::new(peer.server_addr)
                            .with_server_name(peer.server_name.clone());
                        let mut connection =
                            endpoint.connect(connect).await.map_err(io::Error::other)?;
                        connection.keep_alive(true).map_err(io::Error::other)?;
                        let (connection, mut acceptor) = connection.split();
                        let closed = Arc::new(AtomicBool::new(false));
                        let ended = closed.clone();
                        let task = tokio::spawn(async move {
                            while let Ok(Some(_stream)) = acceptor.accept().await {}
                            ended.store(true, Ordering::Release);
                        });
                        *current = Some(Arc::new(S2nGeneration {
                            connection,
                            _endpoint: endpoint.clone(),
                            closed,
                            _reject: RejectTask(task),
                        }));
                    }
                    current.as_ref().unwrap().clone()
                };
                let tunnel = generation.connection.clone().open_tunnel().await?;
                Ok(relay_stream(tunnel, Some(Box::new(generation))))
            }
        }
    }
}

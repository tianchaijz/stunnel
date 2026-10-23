use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::TlsStream;
use crate::tunnel::upstream::Forwarding;

pub struct Config {
    pub addr: SocketAddr,
    pub cert: PathBuf,
    pub priv_key: PathBuf,
}

pub struct Acceptor {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl Acceptor {
    pub async fn accept(&self) -> std::io::Result<Accepting> {
        let (stream, _) = self.listener.accept().await?;
        let acceptor = self.acceptor.clone();
        Ok(Accepting { stream, acceptor })
    }
}

pub struct Accepting {
    stream: TcpStream,
    acceptor: TlsAcceptor,
}

impl Accepting {
    pub async fn accept(self) -> std::io::Result<TlsStream> {
        let stream = self.acceptor.accept(self.stream).await?;
        Ok(TlsStream::Server(stream))
    }
}

pub async fn new(config: &Config) -> std::io::Result<Acceptor> {
    new_server(config).await.map_err(std::io::Error::other)
}

async fn new_server(config: &Config) -> Result<Acceptor, Box<dyn Error + Send + Sync>> {
    let acceptor = tls_acceptor(config, false)?;
    let listener = TcpListener::bind(config.addr).await?;
    Ok(Acceptor { listener, acceptor })
}

pub(crate) fn tls_acceptor(
    config: &Config,
    anytls: bool,
) -> Result<TlsAcceptor, Box<dyn Error + Send + Sync>> {
    let cert = CertificateDer::from_pem_file(&config.cert)?;
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key)?;

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone())?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(certs), provider.clone()).build()?;

    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], priv_key)?;
    server_config.alpn_protocols = vec![b"stunnel".to_vec()];

    if anytls {
        server_config
            .alpn_protocols
            .push(crate::anytls::ALPN.to_vec());
    }
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

const MAX_HANDSHAKES: usize = 64;
const ADMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve legacy TLS and optional AnyTLS on the main TCP address.
/// At most 64 TLS handshakes run concurrently, independently of AnyTLS sessions.
pub async fn serve(config: &crate::config::ServerConfig) -> std::io::Result<()> {
    let route = Forwarding::from_peers(&config.upstreams)?;
    serve_routed(config, route).await
}

/// Serve TCP using a route shared with the process's QUIC listener.
pub async fn serve_routed(
    config: &crate::config::ServerConfig,
    route: Forwarding,
) -> std::io::Result<()> {
    config.validate()?;
    let acceptor = tls_acceptor(
        &Config {
            addr: config.listen,
            cert: config.cert.clone(),
            priv_key: config.priv_key.clone(),
        },
        config.anytls.is_some(),
    )
    .map_err(std::io::Error::other)?;
    let listener = TcpListener::bind(config.listen).await?;
    let anytls = config
        .anytls
        .as_ref()
        .map(|options| Arc::new(crate::anytls::Server::new(options.password.clone())));
    serve_listener(listener, acceptor, anytls, route).await
}

pub(crate) async fn serve_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    anytls: Option<Arc<crate::anytls::Server>>,
    route: Forwarding,
) -> std::io::Result<()> {
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, _) = accepted?;
                let deadline = tokio::time::Instant::now() + ADMISSION_TIMEOUT;
                let Ok(permit) = handshakes.clone().try_acquire_owned() else { continue; };
                let acceptor = acceptor.clone();
                let anytls = anytls.clone();
                let route = route.clone();
                tasks.spawn(async move {
                    let result = async {
                        tcp.set_nodelay(true)?;
                        let stream = tokio::time::timeout_at(deadline, acceptor.accept(tcp)).await
                            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS admission timed out"))??;
                        drop(permit);
                        if tokio::time::Instant::now() >= deadline {
                            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS admission timed out"));
                        }
                        let protocol = stream.get_ref().1.alpn_protocol().map(Vec::from);
                        let result = if protocol.as_deref() == Some(crate::anytls::ALPN) {
                            anytls.as_ref().expect("advertised AnyTLS must be enabled").accept(stream, deadline, route).await
                        } else {
                            let _connection = crate::metrics::TransportConnection::established("tlstcp");
                            let (reader, writer) = super::split(TlsStream::Server(stream));
                            crate::tunnel::server::handle_routed_forward(writer, reader, &route).await.map(|_| ())
                        };
                        if let Err(error) = &result {
                            log::debug!("TCP protocol {protocol:?} ended: {error}");
                        }
                        result
                    }.await;
                    if let Err(error) = result { log::debug!("TCP connection ended: {error}"); }
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = completed { log::error!("TCP task failed: {error}"); }
            }
        }
    }
}

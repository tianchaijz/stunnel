use super::{OpenTunnel, Tunnel};
use crate::{
    config::{PeerConfig, TunnelType},
    metrics::TransportConnection,
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
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

pub const MAX_RELAY_FLOWS: usize = 64;
pub const RELAY_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) struct RelayAdmission {
    _permit: OwnedSemaphorePermit,
    pub(crate) deadline: tokio::time::Instant,
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
        Self::from_peers(peer.map_or(&[], std::slice::from_ref))
    }
    pub fn from_peers(peers: &[PeerConfig]) -> io::Result<Self> {
        if peers.is_empty() {
            return Ok(Self::Direct);
        }
        Ok(Self::Upstream(Arc::new(Upstream {
            route: Arc::new(ForwardRoute::new(peers)?),
            flows: Arc::new(Semaphore::new(MAX_RELAY_FLOWS)),
        })))
    }
}

struct PeerTransport {
    transport: Transport,
}

enum Transport {
    #[cfg(test)]
    Test(TestTransport),
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
type RelayStream = super::transport::OwnedIo<Box<dyn Duplex>, Option<Box<dyn Send>>>;

fn relay_stream(stream: impl Duplex + 'static, owner: Option<Box<dyn Send>>) -> ForwardStream {
    ForwardStream(super::transport::OwnedIo {
        stream: Box::new(stream),
        _owner: owner,
    })
}

impl PeerTransport {
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
        Ok(Self { transport })
    }

    async fn open(&self) -> Result<ForwardStream, OpenError> {
        match &self.transport {
            #[cfg(test)]
            Transport::Test(open) => open().await,
            Transport::Tls(connector) => Ok(relay_stream(
                connector.clone().open_tunnel().await.map_err(|error| {
                    TransportConnection::failed("tlstcp");
                    OpenError::tls(error)
                })?,
                Some(Box::new(TransportConnection::established("tlstcp"))),
            )),
            Transport::AnyTls(connector) => Ok(relay_stream(
                connector
                    .clone()
                    .open_tunnel()
                    .await
                    .map_err(OpenError::anytls)?,
                None,
            )),
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
                            .map_err(|error| {
                                TransportConnection::failed("quic");
                                io::Error::other(error)
                            })?
                            .await
                            .map_err(|error| {
                                TransportConnection::failed("quic");
                                OpenError::quinn(error)
                            })?;
                        let metrics = TransportConnection::established("quic");
                        let reject = connection.clone();
                        let task = tokio::spawn(async move {
                            let _connection = metrics;
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
                let (send, recv) = generation
                    .connection
                    .open_bi()
                    .await
                    .map_err(OpenError::quinn)?;
                let tunnel = Tunnel::new(send, recv);
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
                        let mut connection = endpoint.connect(connect).await.map_err(|error| {
                            TransportConnection::failed("s2n-quic");
                            OpenError::s2n(error)
                        })?;
                        let metrics = TransportConnection::established("s2n-quic");
                        connection.keep_alive(true).map_err(io::Error::other)?;
                        let (connection, mut acceptor) = connection.split();
                        let closed = Arc::new(AtomicBool::new(false));
                        let ended = closed.clone();
                        let task = tokio::spawn(async move {
                            let _connection = metrics;
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
                let stream = generation
                    .connection
                    .clone()
                    .open_bidirectional_stream()
                    .await
                    .map_err(OpenError::s2n)?;
                let (recv, send) = stream.split();
                let tunnel = Tunnel::new(send, recv);
                Ok(relay_stream(tunnel, Some(Box::new(generation))))
            }
        }
    }
}

#[derive(Clone)]
pub struct ConnectionForward<O>(O);

impl<O> ConnectionForward<O> {
    pub fn new(opener: O) -> Self {
        Self(opener)
    }
}

pub enum ForwardRequest {
    Tcp(String),
    Udp,
}

pub struct BoundTunnel<S, R> {
    pub tunnel: Tunnel<S, R>,
    pub bind: BindAddress,
}

pub struct BindAddress {
    text: String,
    address: std::net::SocketAddr,
}

impl BindAddress {
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        self.address
    }
    pub(crate) async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u8(self.text.len() as u8).await?;
        writer.write_all(self.text.as_bytes()).await
    }
}

#[async_trait::async_trait]
pub trait SetupForward: Clone + Send + 'static {
    type S: AsyncWrite + Send + Unpin;
    type R: AsyncRead + Send + Unpin;
    async fn setup(
        &mut self,
        request: &ForwardRequest,
        deadline: Instant,
    ) -> io::Result<BoundTunnel<Self::S, Self::R>>;
}

async fn establish<S: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
    mut tunnel: Tunnel<S, R>,
    request: &ForwardRequest,
) -> io::Result<BoundTunnel<S, R>> {
    match request {
        ForwardRequest::Tcp(target) => {
            tunnel.write_u8(super::TYPE_TCP_FWD).await?;
            tunnel.write_str8(target).await?;
        }
        ForwardRequest::Udp => tunnel.write_u8(super::TYPE_UDP_FWD).await?,
    }
    tunnel.flush().await?;
    let (text, address) = super::protocol::read_bind(&mut tunnel).await?;
    Ok(BoundTunnel {
        tunnel,
        bind: BindAddress { text, address },
    })
}

#[async_trait::async_trait]
impl<O: OpenTunnel> SetupForward for ConnectionForward<O> {
    type S = O::S;
    type R = O::R;
    async fn setup(
        &mut self,
        request: &ForwardRequest,
        deadline: Instant,
    ) -> io::Result<BoundTunnel<Self::S, Self::R>> {
        if Instant::now() >= deadline {
            return Err(setup_timeout());
        }
        tokio::time::timeout_at(deadline, async {
            establish(self.0.open_tunnel().await?, request).await
        })
        .await
        .map_err(|_| setup_timeout())?
    }
}

fn setup_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "forward setup timed out")
}

const COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_ATTEMPT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy)]
enum HealthState {
    Ready,
    Cooling(Instant),
    Probing(Instant),
}
struct Health {
    epoch: u64,
    state: HealthState,
}
impl Default for Health {
    fn default() -> Self {
        Self {
            epoch: 0,
            state: HealthState::Ready,
        }
    }
}
impl Health {
    fn eligible(&self, now: Instant) -> bool {
        match self.state {
            HealthState::Ready => true,
            HealthState::Cooling(until) => now >= until,
            HealthState::Probing(_) => false,
        }
    }
}
struct Lease<'a> {
    health: &'a std::sync::Mutex<Health>,
    epoch: u64,
    probe: bool,
    finished: bool,
}
impl<'a> Lease<'a> {
    fn take(health: &'a std::sync::Mutex<Health>, now: Instant) -> Option<Self> {
        let mut state = health.lock().unwrap();
        if !state.eligible(now) {
            return None;
        }
        let probe = if let HealthState::Cooling(until) = state.state {
            state.epoch += 1;
            state.state = HealthState::Probing(until);
            true
        } else {
            false
        };
        Some(Self {
            health,
            epoch: state.epoch,
            probe,
            finished: false,
        })
    }
    fn finish(mut self, evidence: Evidence) {
        let mut health = self.health.lock().unwrap();
        if health.epoch == self.epoch {
            if matches!(evidence, Evidence::PeerFailure) {
                health.state = HealthState::Cooling(Instant::now() + COOLDOWN);
                health.epoch += 1;
            } else if self.probe {
                health.state = HealthState::Ready;
                health.epoch += 1;
            }
        }
        self.finished = true;
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if self.finished || !self.probe {
            return;
        }
        let mut health = self.health.lock().unwrap();
        if health.epoch == self.epoch
            && let HealthState::Probing(until) = health.state
        {
            health.state = HealthState::Cooling(until);
            health.epoch += 1;
        }
    }
}

#[derive(Clone, Copy)]
enum Evidence {
    Neutral,
    PeerFailure,
}
struct OpenError {
    error: io::Error,
    evidence: Evidence,
}
impl From<io::Error> for OpenError {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            evidence: Evidence::Neutral,
        }
    }
}
impl OpenError {
    fn remote(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            error: io::Error::other(error),
            evidence: Evidence::PeerFailure,
        }
    }
    fn quinn(error: quinn::ConnectionError) -> Self {
        match error {
            quinn::ConnectionError::LocallyClosed | quinn::ConnectionError::CidsExhausted => {
                Self::from(io::Error::other(error))
            }
            _ => Self::remote(error),
        }
    }
    fn s2n(error: s2n_quic::connection::Error) -> Self {
        use s2n_quic::connection::Error;
        use s2n_quic_core::endpoint::Location;
        match error {
            Error::Closed {
                initiator: Location::Remote,
                ..
            }
            | Error::Transport {
                initiator: Location::Remote,
                ..
            }
            | Error::Application {
                initiator: Location::Remote,
                ..
            }
            | Error::StatelessReset { .. }
            | Error::IdleTimerExpired { .. }
            | Error::MaxHandshakeDurationExceeded { .. } => Self::remote(error),
            _ => Self::from(io::Error::other(error)),
        }
    }
    fn anytls(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::TimedOut {
            Self::from(error)
        } else {
            Self::tls(error)
        }
    }
    fn tls(error: io::Error) -> Self {
        let evidence = match error.kind() {
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::TimedOut => Evidence::PeerFailure,
            _ => Evidence::Neutral,
        };
        Self { error, evidence }
    }
}

struct Peer {
    transport: PeerTransport,
    health: std::sync::Mutex<Health>,
}
pub struct ForwardRoute {
    peers: Box<[Peer]>,
}
impl ForwardRoute {
    pub fn new(peers: &[PeerConfig]) -> io::Result<Self> {
        if peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "route requires at least one peer",
            ));
        }
        let peers = peers
            .iter()
            .map(|peer| {
                Ok(Peer {
                    transport: PeerTransport::new(peer)?,
                    health: std::sync::Mutex::default(),
                })
            })
            .collect::<io::Result<_>>()?;
        Ok(Self { peers })
    }
    async fn setup(
        &self,
        request: &ForwardRequest,
        deadline: Instant,
    ) -> io::Result<
        BoundTunnel<tokio::io::WriteHalf<ForwardStream>, tokio::io::ReadHalf<ForwardStream>>,
    > {
        let mut last = io::Error::new(
            io::ErrorKind::NotConnected,
            "all forward peers are cooling or probing",
        );
        for (index, peer) in self.peers.iter().enumerate() {
            let now = Instant::now();
            let remaining = deadline
                .checked_duration_since(now)
                .filter(|d| !d.is_zero())
                .ok_or_else(setup_timeout)?;
            let (lease, budget) = if self.peers.len() == 1 {
                (None, remaining)
            } else {
                let eligible = self.peers[index..]
                    .iter()
                    .filter(|p| p.health.lock().unwrap().eligible(now))
                    .count();
                let Some(lease) = Lease::take(&peer.health, now) else {
                    continue;
                };
                (
                    Some(lease),
                    (remaining / eligible.max(1) as u32).min(MAX_ATTEMPT),
                )
            };
            let result = tokio::time::timeout_at(now + budget, async {
                let stream = peer.transport.open().await?;
                let (reader, writer) = tokio::io::split(stream);
                establish(Tunnel::new(writer, reader), request)
                    .await
                    .map_err(OpenError::from)
            })
            .await
            .unwrap_or_else(|_| Err(setup_timeout().into()));
            if let Some(lease) = lease {
                lease.finish(
                    result
                        .as_ref()
                        .err()
                        .map_or(Evidence::Neutral, |e| e.evidence),
                );
            }
            match result {
                Ok(bound) => return Ok(bound),
                Err(error) => {
                    last = io::Error::new(
                        error.error.kind(),
                        format!("forward peer {} setup: {}", index + 1, error.error),
                    )
                }
            }
        }
        if Instant::now() >= deadline {
            Err(setup_timeout())
        } else {
            Err(last)
        }
    }
}

#[async_trait::async_trait]
impl SetupForward for Arc<ForwardRoute> {
    type S = tokio::io::WriteHalf<ForwardStream>;
    type R = tokio::io::ReadHalf<ForwardStream>;
    async fn setup(
        &mut self,
        request: &ForwardRequest,
        deadline: Instant,
    ) -> io::Result<BoundTunnel<Self::S, Self::R>> {
        ForwardRoute::setup(self, request, deadline).await
    }
}

pub struct Upstream {
    route: Arc<ForwardRoute>,
    flows: Arc<Semaphore>,
}
impl Upstream {
    pub(crate) fn admit(&self) -> io::Result<RelayAdmission> {
        self.flows
            .clone()
            .try_acquire_owned()
            .map(|permit| RelayAdmission {
                _permit: permit,
                deadline: Instant::now() + RELAY_SETUP_TIMEOUT,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "relay flow limit reached"))
    }
    pub(crate) async fn setup(
        &self,
        request: &ForwardRequest,
        deadline: Instant,
    ) -> io::Result<
        BoundTunnel<tokio::io::WriteHalf<ForwardStream>, tokio::io::ReadHalf<ForwardStream>>,
    > {
        ForwardRoute::setup(&self.route, request, deadline).await
    }
}

pub struct ForwardStream(RelayStream);
impl AsyncRead for ForwardStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for ForwardStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
type TestTransport = Box<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ForwardStream, OpenError>> + Send>,
        > + Send
        + Sync,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::atomic::AtomicUsize, time::Duration};
    use tokio::{io::AsyncReadExt, sync::Notify};

    enum Action {
        Bind(&'static str),
        Fail(Evidence),
        Hang,
        StallBind,
        Wait(Arc<Notify>, Result<&'static str, Evidence>),
    }

    fn peer(actions: Vec<Action>) -> (Peer, Arc<AtomicUsize>) {
        let actions = std::sync::Mutex::new(VecDeque::from(actions));
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let open = Box::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            let action = actions
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected peer attempt");
            Box::pin(async move {
                let result = match action {
                    Action::Bind(bind) => Ok(Some(bind)),
                    Action::StallBind => Ok(None),
                    Action::Fail(evidence) => Err(evidence),
                    Action::Hang => std::future::pending().await,
                    Action::Wait(gate, result) => {
                        gate.notified().await;
                        result.map(Some)
                    }
                };
                let bind = result.map_err(|evidence| OpenError {
                    error: io::Error::other("test open failure"),
                    evidence,
                })?;
                let (client, mut server) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let kind = server.read_u8().await.unwrap();
                    if kind == super::super::TYPE_TCP_FWD {
                        let length = server.read_u8().await.unwrap();
                        let mut target = vec![0; length as usize];
                        server.read_exact(&mut target).await.unwrap();
                    }
                    if let Some(bind) = bind {
                        server.write_u8(bind.len() as u8).await.unwrap();
                        server.write_all(bind.as_bytes()).await.unwrap();
                    } else {
                        server.read_to_end(&mut Vec::new()).await.unwrap();
                    }
                });
                Ok(relay_stream(client, None))
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<ForwardStream, OpenError>> + Send>,
                >
        });
        (
            Peer {
                transport: PeerTransport {
                    transport: Transport::Test(open),
                },
                health: std::sync::Mutex::default(),
            },
            calls,
        )
    }
    fn route(peers: Vec<Peer>) -> Arc<ForwardRoute> {
        Arc::new(ForwardRoute {
            peers: peers.into_boxed_slice(),
        })
    }
    async fn setup(
        route: &ForwardRoute,
    ) -> io::Result<
        BoundTunnel<tokio::io::WriteHalf<ForwardStream>, tokio::io::ReadHalf<ForwardStream>>,
    > {
        route
            .setup(
                &ForwardRequest::Tcp("target:80".into()),
                Instant::now() + RELAY_SETUP_TIMEOUT,
            )
            .await
    }
    fn count(calls: &AtomicUsize) -> usize {
        calls.load(Ordering::SeqCst)
    }
    async fn wait_calls(calls: &AtomicUsize, expected: usize) {
        while count(calls) < expected {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ordered_retry_cooldown_failback_and_raw_bind() {
        let (primary, pc) = peer(vec![
            Action::Fail(Evidence::PeerFailure),
            Action::Bind("[0:0:0:0:0:0:0:1]:80"),
        ]);
        let (backup, bc) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![primary, backup]);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(count(&pc), 1);
        tokio::time::advance(COOLDOWN).await;
        assert_eq!(
            setup(&route).await.unwrap().bind.text,
            "[0:0:0:0:0:0:0:1]:80"
        );
        assert_eq!(count(&pc), 2);
        assert_eq!(count(&bc), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn neutral_open_and_invalid_bind_retry_without_cooling() {
        let (primary, pc) = peer(vec![
            Action::Fail(Evidence::Neutral),
            Action::Bind("invalid"),
            Action::Bind("127.0.0.1:80"),
        ]);
        let (backup, _) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![primary, backup]);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 80);
        assert_eq!(count(&pc), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn all_cooling_fails_immediately_and_singleton_reconnects() {
        let (a, ac) = peer(vec![Action::Fail(Evidence::PeerFailure)]);
        let (b, bc) = peer(vec![Action::Fail(Evidence::PeerFailure)]);
        let route = route(vec![a, b]);
        assert!(setup(&route).await.is_err());
        let start = Instant::now();
        assert_eq!(
            setup(&route).await.err().unwrap().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(Instant::now(), start);
        assert_eq!((count(&ac), count(&bc)), (1, 1));
        let (a, ac) = peer(vec![
            Action::Fail(Evidence::PeerFailure),
            Action::Bind("127.0.0.1:80"),
        ]);
        let singleton = super::tests::route(vec![a]);
        assert!(setup(&singleton).await.is_err());
        assert!(setup(&singleton).await.is_ok());
        assert_eq!(count(&ac), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn fair_budget_gives_three_blackholes_a_turn_and_singleton_ten_seconds() {
        let (a, ac) = peer(vec![Action::Hang]);
        let (b, bc) = peer(vec![Action::Hang]);
        let (c, cc) = peer(vec![Action::Hang]);
        let route = route(vec![a, b, c]);
        let start = Instant::now();
        assert_eq!(
            setup(&route).await.err().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(Instant::now() - start, RELAY_SETUP_TIMEOUT);
        assert_eq!((count(&ac), count(&bc), count(&cc)), (1, 1, 1));
        let (a, _) = peer(vec![Action::Hang]);
        let singleton = super::tests::route(vec![a]);
        let start = Instant::now();
        assert!(setup(&singleton).await.is_err());
        assert_eq!(Instant::now() - start, RELAY_SETUP_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_probe_releases_ownership_and_concurrent_flow_skips_probe() {
        let gate = Arc::new(Notify::new());
        let (a, ac) = peer(vec![
            Action::Fail(Evidence::PeerFailure),
            Action::Wait(gate, Ok("127.0.0.1:80")),
            Action::Bind("127.0.0.1:80"),
        ]);
        let (b, bc) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![a, b]);
        setup(&route).await.unwrap();
        tokio::time::advance(COOLDOWN).await;
        let other = route.clone();
        let probing = tokio::spawn(async move { setup(&other).await });
        wait_calls(&ac, 2).await;
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(count(&ac), 2);
        probing.abort();
        assert!(probing.await.err().unwrap().is_cancelled());
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 80);
        assert_eq!(count(&bc), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_ready_success_cannot_clear_new_failure() {
        let gate = Arc::new(Notify::new());
        let (a, ac) = peer(vec![
            Action::Wait(gate.clone(), Ok("127.0.0.1:80")),
            Action::Fail(Evidence::PeerFailure),
        ]);
        let (b, _) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![a, b]);
        let other = route.clone();
        let first = tokio::spawn(async move { setup(&other).await });
        wait_calls(&ac, 1).await;
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        gate.notify_one();
        assert_eq!(first.await.unwrap().unwrap().bind.socket_addr().port(), 80);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(count(&ac), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn ordinary_success_does_not_discard_sibling_failure() {
        let gate = Arc::new(Notify::new());
        let (a, ac) = peer(vec![
            Action::Wait(gate.clone(), Err(Evidence::PeerFailure)),
            Action::Bind("127.0.0.1:80"),
        ]);
        let (b, _) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![a, b]);
        let other = route.clone();
        let first = tokio::spawn(async move { setup(&other).await });
        wait_calls(&ac, 1).await;
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 80);
        gate.notify_one();
        assert_eq!(first.await.unwrap().unwrap().bind.socket_addr().port(), 81);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(count(&ac), 2);
    }

    #[test]
    fn capacity_and_opaque_errors_are_neutral() {
        for error in [
            quinn::ConnectionError::CidsExhausted,
            quinn::ConnectionError::LocallyClosed,
        ] {
            assert!(matches!(
                OpenError::quinn(error).evidence,
                Evidence::Neutral
            ));
        }
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Other,
            io::ErrorKind::InvalidInput,
        ] {
            assert!(matches!(
                OpenError::tls(io::Error::from(kind)).evidence,
                Evidence::Neutral
            ));
        }
        assert!(matches!(
            OpenError::tls(io::Error::from(io::ErrorKind::ConnectionRefused)).evidence,
            Evidence::PeerFailure
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn relay_permit_and_original_deadline_cover_all_peers() {
        let (a, _) = peer(vec![Action::Hang]);
        let (b, bc) = peer(vec![Action::Bind("127.0.0.1:81")]);
        let upstream = Arc::new(Upstream {
            route: route(vec![a, b]),
            flows: Arc::new(Semaphore::new(MAX_RELAY_FLOWS)),
        });
        let admission = upstream.admit().unwrap();
        let permits: Vec<_> = (1..MAX_RELAY_FLOWS)
            .map(|_| upstream.clone().admit().unwrap())
            .collect();
        assert_eq!(
            upstream.admit().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        tokio::time::advance(Duration::from_secs(8)).await;
        let bound = upstream
            .setup(&ForwardRequest::Udp, admission.deadline)
            .await
            .unwrap();
        assert_eq!(bound.bind.socket_addr().port(), 81);
        assert_eq!(count(&bc), 1);
        assert_eq!(
            upstream.admit().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            admission.setup(async { Ok(()) }).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(admission);
        assert!(upstream.admit().is_ok());
        drop(permits);
    }
    #[tokio::test(start_paused = true)]
    async fn post_open_timeout_is_neutral_and_expired_probe_resets_on_neutral_failure() {
        let (a, ac) = peer(vec![
            Action::Fail(Evidence::PeerFailure),
            Action::StallBind,
            Action::Bind("127.0.0.1:80"),
        ]);
        let (b, _) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![a, b]);
        setup(&route).await.unwrap();
        tokio::time::advance(COOLDOWN).await;
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 80);
        assert_eq!(count(&ac), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_ready_failure_cannot_cool_a_new_probe_generation() {
        let gate = Arc::new(Notify::new());
        let (a, ac) = peer(vec![
            Action::Wait(gate.clone(), Err(Evidence::PeerFailure)),
            Action::Fail(Evidence::PeerFailure),
            Action::Bind("127.0.0.1:80"),
            Action::Bind("127.0.0.1:80"),
        ]);
        let (b, _) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![a, b]);
        let other = route.clone();
        let first = tokio::spawn(async move {
            let lease = Lease::take(&other.peers[0].health, Instant::now()).unwrap();
            let error = other.peers[0].transport.open().await.err().unwrap();
            lease.finish(error.evidence);
        });
        wait_calls(&ac, 1).await;
        setup(&route).await.unwrap();
        tokio::time::advance(COOLDOWN).await;
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 80);
        gate.notify_one();
        first.await.unwrap();
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 80);
    }

    struct Identity {
        directory: std::path::PathBuf,
        config: PeerConfig,
    }
    impl Identity {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let directory = std::env::temp_dir().join(format!(
                "stunnel-route-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let server_cert = directory.join("cert.pem");
            let private_key = directory.join("key.pem");
            std::fs::write(&server_cert, cert.pem()).unwrap();
            std::fs::write(&private_key, key_pair.serialize_pem()).unwrap();
            Self {
                directory,
                config: PeerConfig {
                    server_addr: "127.0.0.1:9".parse().unwrap(),
                    server_name: "localhost".into(),
                    server_cert,
                    private_key,
                    tunnel_type: TunnelType::Quinn,
                    anytls: Some(crate::config::ClientAnyTlsConfig {
                        password: "test".into(),
                    }),
                    quic: Default::default(),
                },
            }
        }
    }
    impl Drop for Identity {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn anytls_local_open_failures_are_neutral() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::Other,
        ] {
            assert!(matches!(
                OpenError::anytls(io::Error::from(kind)).evidence,
                Evidence::Neutral
            ));
        }
    }

    #[tokio::test]
    async fn anytls_refused_connect_falls_back_and_cools_peer() {
        let mut identity = Identity::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        identity.config.server_addr = address;
        identity.config.tunnel_type = TunnelType::AnyTls;
        let primary = Peer {
            transport: PeerTransport::new(&identity.config).unwrap(),
            health: std::sync::Mutex::default(),
        };
        let (backup, calls) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![primary, backup]);
        assert_eq!(setup(&route).await.unwrap().bind.socket_addr().port(), 81);
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), setup(&route))
                .await
                .unwrap()
                .unwrap()
                .bind
                .socket_addr()
                .port(),
            81
        );
        assert_eq!(count(&calls), 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn every_backup_is_built_before_route_is_available() {
        let identity = Identity::new();
        for transport in [
            TunnelType::TlsTcp,
            TunnelType::AnyTls,
            TunnelType::Quinn,
            TunnelType::S2nQuic,
        ] {
            let mut backup = identity.config.clone();
            backup.tunnel_type = transport;
            assert!(ForwardRoute::new(&[identity.config.clone(), backup.clone()]).is_ok());
            backup.server_cert = identity.directory.join("missing.pem");
            assert!(ForwardRoute::new(&[identity.config.clone(), backup.clone()]).is_err());
            backup.server_cert = identity.config.server_cert.clone();
            backup.server_name = "invalid server name".into();
            assert!(ForwardRoute::new(&[identity.config.clone(), backup]).is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cache_lock_timeout_does_not_cool_peer() {
        let identity = Identity::new();
        let primary = Peer {
            transport: PeerTransport::new(&identity.config).unwrap(),
            health: std::sync::Mutex::default(),
        };
        let (backup, bc) = peer(vec![
            Action::Bind("127.0.0.1:81"),
            Action::Bind("127.0.0.1:81"),
        ]);
        let route = route(vec![primary, backup]);
        let Transport::Quinn { current, .. } = &route.peers[0].transport.transport else {
            unreachable!()
        };
        let _lock = current.lock().await;
        let start = Instant::now();
        assert!(setup(&route).await.is_ok());
        assert!(Instant::now() - start >= MAX_ATTEMPT);
        let start = Instant::now();
        assert!(setup(&route).await.is_ok());
        assert!(Instant::now() - start >= MAX_ATTEMPT);
        assert_eq!(count(&bc), 2);
    }
}

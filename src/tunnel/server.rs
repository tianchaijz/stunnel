use std::{future::Future, pin::Pin};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::tunnel::{
    AcceptTunnel, AsyncReadDatagramExt, AsyncWriteDatagramExt, CTRL_ACK, CTRL_ERR,
    CTRL_REGISTER_REVERSE, CTRL_REGISTER_REVERSE_END, OpenTunnel, TYPE_CONTROL, TYPE_TCP_FWD,
    TYPE_TCP_REV, TYPE_UDP_FWD, Tunnel,
};

use super::upstream::{ForwardRequest, Forwarding, RelayAdmission, Upstream};

pub async fn handle_routed_tunnels<O, A>(
    opener: O,
    mut acceptor: A,
    route: Forwarding,
) -> std::io::Result<()>
where
    O: OpenTunnel,
    A: AcceptTunnel,
{
    let Forwarding::Upstream(upstream) = route else {
        return handle_all_kinds_tunnels(opener, acceptor).await;
    };
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            incoming = acceptor.accept_tunnel() => {
                let tunnel = incoming?;
                let Ok(admission) = upstream.admit() else { continue; };
                let upstream = upstream.clone();
                tasks.spawn(async move {
                    if let Err(error) = relay(tunnel, &upstream, admission).await {
                        log::debug!("relay stream ended: {error}");
                    }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

pub async fn handle_routed_forward<S, R>(
    send: S,
    recv: R,
    route: &Forwarding,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    match route {
        Forwarding::Direct => handle_forward_tunnel(send, recv).await,
        Forwarding::Upstream(upstream) => {
            relay(Tunnel::new(send, recv), upstream, upstream.admit()?).await
        }
    }
}

pub(crate) async fn relay<S, R>(
    tunnel: Tunnel<S, R>,
    upstream: &Upstream,
    admission: RelayAdmission,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let (mut downstream, mut outbound) = admission
        .setup(async {
            let incoming = into_incoming(tunnel).await?;
            let (mut downstream, request) = match incoming {
                Incoming::Tcp((tunnel, destination)) => (tunnel, ForwardRequest::Tcp(destination)),
                Incoming::Udp(tunnel) => (tunnel, ForwardRequest::Udp),
                Incoming::Control(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "reverse control is unsupported in relay mode",
                    ));
                }
            };
            let bound = upstream.setup(&request, admission.deadline).await?;
            bound.bind.write_to(&mut downstream).await?;
            let outbound = bound.tunnel;
            downstream.flush().await?;
            Ok::<_, std::io::Error>((downstream, outbound))
        })
        .await?;
    copy_bidirectional(&mut downstream, &mut outbound).await
}

enum Incoming<S, R> {
    Udp(Tunnel<S, R>),
    Tcp((Tunnel<S, R>, String)),
    Control(Tunnel<S, R>),
}

// Reads the tunnel type of a tunnel and classifies it into Incoming.
async fn into_incoming<S, R>(mut tun: Tunnel<S, R>) -> std::io::Result<Incoming<S, R>>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    match tun.read_u8().await? {
        TYPE_UDP_FWD => Ok(Incoming::Udp(tun)),
        TYPE_TCP_FWD => {
            let addr = tun.read_str8().await?;
            Ok(Incoming::Tcp((tun, addr)))
        }
        TYPE_CONTROL => Ok(Incoming::Control(tun)),
        typ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid tunnel type: {typ}"),
        )),
    }
}

// Handles one connection: accepts tunnels and spawns a task per tunnel, so
// reading the tunnel type of one tunnel never blocks accepting the others.
// The control tunnel task owns the reverse listeners of the connection: they
// are joined with the control tunnel and end when it dies, and the control
// tunnel is finished so the client reconnects and re-registers.
pub async fn handle_all_kinds_tunnels<O, A>(opener: O, mut acceptor: A) -> std::io::Result<()>
where
    O: OpenTunnel,
    A: AcceptTunnel,
{
    loop {
        let tun = acceptor.accept_tunnel().await?;

        let opener = opener.clone();

        tokio::spawn(async move {
            match into_incoming(tun).await {
                Ok(Incoming::Control(tun)) => {
                    // the control tunnel is the liveness signal of the
                    // connection: when it dies, the joined reverse listeners
                    // end with it, and the tunnel is finished so the client
                    // reconnects and re-registers
                    handle_control_tunnel(tun, opener)
                        .await
                        .inspect_err(|error| {
                            log::error!("control tunnel error: {error}");
                        })
                        .ok();
                }
                Ok(Incoming::Udp(tun)) => {
                    handle_udp_tunnel(tun)
                        .await
                        .inspect_err(|error| {
                            log::error!("handle udp tunnel error: {error}");
                        })
                        .ok();
                }
                Ok(Incoming::Tcp((tun, destination))) => {
                    handle_tcp_tunnel(tun, destination)
                        .await
                        .inspect_err(|error| {
                            log::error!("handle tcp tunnel error: {error}");
                        })
                        .ok();
                }
                Err(error) => {
                    log::error!("accept tunnel error: {error}");
                }
            }
        });
    }
}

// Dispatches a forward tunnel: TCP/UDP tunnels are handled here, a control
// tunnel is a protocol error.
pub async fn handle_forward_tunnel<S, R>(send: S, recv: R) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    match into_incoming(Tunnel::new(send, recv)).await? {
        Incoming::Udp(tun) => handle_udp_tunnel(tun).await,
        Incoming::Tcp((tun, destination)) => handle_tcp_tunnel(tun, destination).await,
        Incoming::Control(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected control tunnel",
        )),
    }
}

async fn handle_tcp_tunnel<S, R>(
    mut tun: Tunnel<S, R>,
    destination: String,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut stream = TcpStream::connect(destination).await?;
    tun.response(stream.local_addr()?).await?;
    copy_bidirectional(&mut tun, &mut stream).await
}

async fn handle_udp_tunnel<S, R>(mut tun: Tunnel<S, R>) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    tun.response(socket.local_addr()?).await?;
    copy_bidirectional_udp_socket(tun, &socket).await
}

async fn copy_bidirectional_udp_socket<S, R>(
    tun: Tunnel<S, R>,
    socket: &UdpSocket,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    async fn r<S>(socket: &UdpSocket, send: &mut S) -> std::io::Result<()>
    where
        S: AsyncWrite + Send + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await?;
            send.send_datagram(&buf[..n], from).await?;
        }
    }

    async fn w<R>(socket: &UdpSocket, recv: &mut R) -> std::io::Result<()>
    where
        R: AsyncRead + Send + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, target) = recv.recv_datagram(&mut buf).await?;
            socket.send_to(&buf[..n], target).await?;
        }
    }

    let (mut send, mut recv) = tun.split();
    futures::try_join!(r(socket, &mut send), w(socket, &mut recv)).map(|_| (0, 0))
}

// Accepts TCP connections on the reverse listener and sends them back to the
// client as reverse tunnels. The client connects to `target` on its side and
// responds with its bind addr, then data is copied bidirectionally.
async fn handle_reverse_tunnels<O>(
    listener: TcpListener,
    target: String,
    opener: O,
) -> std::io::Result<()>
where
    O: OpenTunnel,
{
    loop {
        let (mut stream, _) = listener.accept().await?;

        let mut opener = opener.clone();
        let target = target.clone();

        tokio::spawn(async move {
            let result = async {
                let mut tun = opener.open_tunnel().await?;

                tun.write_u8(TYPE_TCP_REV).await?;
                tun.write_str8(&target).await?;

                // client connects to its local target and responds with its bind addr
                tun.read_str8().await?;

                copy_bidirectional(&mut tun, &mut stream).await?;
                Ok::<(), std::io::Error>(())
            }
            .await;

            if let Err(error) = result {
                log::error!("reverse tunnel to {target} error: {error}");
            }
        });
    }
}

// Handles the control tunnel of a connection. Reads reverse proxy
// registrations and binds their listeners until the client signals the end of
// registration, then holds the control tunnel together with the listeners so
// they all end when any of them fails, typically the control tunnel dying.
// Dropping the tunnel finishes its stream so the client reconnects and
// re-registers.
async fn handle_control_tunnel<S, R, O>(mut tun: Tunnel<S, R>, opener: O) -> std::io::Result<()>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    O: OpenTunnel,
{
    let mut listeners = Vec::new();
    loop {
        match tun.read_u8().await? {
            CTRL_REGISTER_REVERSE => {
                let listen = tun.read_str8().await?;
                let target = tun.read_str8().await?;

                match TcpListener::bind(&listen).await {
                    Ok(listener) => {
                        let bind = listener.local_addr()?.to_string();
                        log::info!("reverse listener {listen} -> {target} bound: {bind}");
                        listeners.push((listener, target));

                        tun.write_u8(CTRL_ACK).await?;
                        tun.write_str8(&bind).await?;
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        tun.write_u8(CTRL_ERR).await?;
                        tun.write_str8(&reason).await?;
                        log::error!("bind reverse listener {listen} failed: {reason}");
                    }
                }
            }
            CTRL_REGISTER_REVERSE_END => break,
            typ => {
                let reason = format!("unknown control message: {typ}");
                tun.write_u8(CTRL_ERR).await?;
                tun.write_str8(&reason).await?;
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, reason));
            }
        }
    }

    // registration done: the control tunnel becomes the holder of the
    // connection, run it together with the reverse listeners
    let mut futs: Vec<Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>> = Vec::new();
    for (listener, target) in listeners {
        futs.push(Box::pin(handle_reverse_tunnels(
            listener,
            target,
            opener.clone(),
        )));
    }
    futs.push(Box::pin(hold_control_tunnel(tun)));

    futures::future::try_join_all(futs).await.map(|_| ())
}

// Holds the control tunnel open after registration: reads until the
// connection dies, ending the joined reverse listeners with it. A closed
// control tunnel is treated as an error so try_join_all tears everything
// down instead of waiting on the never-ending listeners.
async fn hold_control_tunnel<S, R>(mut tun: Tunnel<S, R>) -> std::io::Result<()>
where
    S: Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut buf = [0u8; 64];
    loop {
        match tun.read(&mut buf).await {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control tunnel closed",
                ));
            }
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use crate::{
        config::{PeerConfig, TunnelType},
        tlstcp,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Exit {
        route: Forwarding,
        acceptor: tlstcp::server::Acceptor,
        directory: PathBuf,
    }
    impl Exit {
        async fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "stunnel-relay-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_path = directory.join("cert.pem");
            let key = directory.join("key.pem");
            std::fs::write(&cert_path, cert.pem()).unwrap();
            std::fs::write(&key, key_pair.serialize_pem()).unwrap();
            let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = reserve.local_addr().unwrap();
            drop(reserve);
            let acceptor = tlstcp::server::new(&tlstcp::server::Config {
                addr,
                cert: cert_path.clone(),
                priv_key: key.clone(),
            })
            .await
            .unwrap();
            let route = Forwarding::new(Some(&PeerConfig {
                server_addr: addr,
                server_name: "localhost".into(),
                server_cert: cert_path,
                private_key: key,
                tunnel_type: TunnelType::TlsTcp,
                anytls: None,
                quic: Default::default(),
            }))
            .unwrap();
            Self {
                route,
                acceptor,
                directory,
            }
        }
    }
    impl Drop for Exit {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn relay_task(
        route: Forwarding,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<std::io::Result<(u64, u64)>>,
    ) {
        let (client, server) = tokio::io::duplex(1024);
        let (recv, send) = tokio::io::split(server);
        let task = tokio::spawn(async move { handle_routed_forward(send, recv, &route).await });
        (client, task)
    }

    #[tokio::test]
    async fn relay_preserves_bind_bytes_and_tcp_half_close() {
        let exit = Exit::new().await;
        let (client, relay) = relay_task(exit.route.clone());
        let (recv, send) = tokio::io::split(client);
        let mut client = Tunnel::new(send, recv);
        client.write_u8(TYPE_TCP_FWD).await.unwrap();
        client.write_str8("example.test:80").await.unwrap();
        let connection = exit
            .acceptor
            .accept()
            .await
            .unwrap()
            .accept()
            .await
            .unwrap();
        let (recv, send) = tlstcp::split(connection);
        let mut upstream = Tunnel::new(send, recv);
        assert_eq!(upstream.read_u8().await.unwrap(), TYPE_TCP_FWD);
        assert_eq!(upstream.read_str8().await.unwrap(), "example.test:80");
        let bind = "[0:0:0:0:0:0:0:1]:1234";
        upstream.write_str8(bind).await.unwrap();
        upstream.flush().await.unwrap();
        assert_eq!(client.read_str8().await.unwrap(), bind);
        tokio::time::pause();
        tokio::time::advance(
            super::super::upstream::RELAY_SETUP_TIMEOUT + std::time::Duration::from_secs(1),
        )
        .await;
        tokio::time::resume();
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        upstream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        upstream.write_all(b"response after EOF").await.unwrap();
        upstream.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after EOF");
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relay_copies_fragmented_and_coalesced_udp_frames_opaquely() {
        let exit = Exit::new().await;
        let (mut client, relay) = relay_task(exit.route.clone());
        client.write_u8(TYPE_UDP_FWD).await.unwrap();
        let connection = exit
            .acceptor
            .accept()
            .await
            .unwrap()
            .accept()
            .await
            .unwrap();
        let (recv, send) = tlstcp::split(connection);
        let mut upstream = Tunnel::new(send, recv);
        assert_eq!(upstream.read_u8().await.unwrap(), TYPE_UDP_FWD);
        upstream.write_str8("127.0.0.1:9876").await.unwrap();
        upstream.flush().await.unwrap();
        assert_eq!(
            super::super::protocol::read_bind(&mut client)
                .await
                .unwrap()
                .1
                .port(),
            9876
        );
        let frames = b"\x0b127.0.0.1:1\x00\x00\x0b127.0.0.1:2\x00\x03\xff\x00\x80";
        for byte in &frames[..9] {
            client.write_all(&[*byte]).await.unwrap();
        }
        client.write_all(&frames[9..]).await.unwrap();
        let mut received = vec![0; frames.len()];
        upstream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, frames);
        upstream.write_all(frames).await.unwrap();
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, frames);
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relay_rejects_invalid_bind_and_control_without_success() {
        let exit = Exit::new().await;
        let (mut client, relay) = relay_task(exit.route.clone());
        client.write_u8(TYPE_UDP_FWD).await.unwrap();
        let connection = exit
            .acceptor
            .accept()
            .await
            .unwrap()
            .accept()
            .await
            .unwrap();
        let (recv, send) = tlstcp::split(connection);
        let mut upstream = Tunnel::new(send, recv);
        upstream.read_u8().await.unwrap();
        upstream.write_str8("not a socket address").await.unwrap();
        upstream.flush().await.unwrap();
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            client.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let (mut client, relay) = relay_task(exit.route.clone());
        client
            .write_all(&[TYPE_CONTROL, CTRL_REGISTER_REVERSE])
            .await
            .unwrap();
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn expired_relay_admission_rejects_even_a_ready_header() {
        let exit = Exit::new().await;
        let Forwarding::Upstream(upstream) = &exit.route else {
            unreachable!()
        };
        let admission = upstream.admit().unwrap();
        let (mut client, server) = tokio::io::duplex(64);
        client.write_u8(TYPE_CONTROL).await.unwrap();
        tokio::time::pause();
        tokio::time::advance(super::super::upstream::RELAY_SETUP_TIMEOUT).await;
        let (recv, send) = tokio::io::split(server);
        assert_eq!(
            relay(Tunnel::new(send, recv), upstream, admission)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            client.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn relay_admission_precedes_header_and_recovers_on_cancel_and_timeout() {
        let exit = Exit::new().await;
        let Forwarding::Upstream(upstream) = &exit.route else {
            unreachable!()
        };
        let mut permits = Vec::new();
        for _ in 0..super::super::upstream::MAX_RELAY_FLOWS - 1 {
            permits.push(upstream.admit().unwrap());
        }
        let (_client, relay) = relay_task(exit.route.clone());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while upstream.admit().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (_client, overflow) = relay_task(exit.route.clone());
        assert_eq!(
            overflow.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
        assert!(upstream.admit().is_ok());
        let (_client, timeout) = relay_task(exit.route.clone());
        assert_eq!(
            timeout.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(upstream.admit().is_ok());
    }
}

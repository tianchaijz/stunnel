use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use stunnel::{
    config::{PeerConfig, TunnelType},
    quic,
    tunnel::{AcceptTunnel, server::handle_routed_forward, upstream::Forwarding},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const BIND: &[u8] = b"127.0.0.1:4321";

struct Certificates(PathBuf);
impl Certificates {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "stunnel-quic-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let guard = Self(path);
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(guard.0.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(guard.0.join("key.pem"), key_pair.serialize_pem()).unwrap();
        guard
    }
}
impl Drop for Certificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn read_string<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let length = reader.read_u8().await?;
    let mut bytes = vec![0; length as usize];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_string<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    writer.write_u8(bytes.len().try_into().unwrap()).await?;
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn serve<A: AcceptTunnel>(
    mut acceptor: A,
    close: oneshot::Receiver<()>,
    shutdown: impl FnOnce() + Send,
) where
    A::S: 'static,
    A::R: 'static,
{
    tokio::pin!(close);
    let mut streams = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut close => { shutdown(); return; }
            stream = acceptor.accept_tunnel() => {
                let Ok(mut stream) = stream else { return; };
                streams.spawn(async move {
                    assert_eq!(stream.read_u8().await.unwrap(), 1);
                    let destination = read_string(&mut stream).await.unwrap();
                    if destination == b"refuse.test:80" { return; }
                    if destination == b"malformed.test:80" {
                        write_string(&mut stream, b"invalid bind").await.unwrap();
                        stream.shutdown().await.unwrap();
                        return;
                    }
                    write_string(&mut stream, BIND).await.unwrap();
                    let mut payload = Vec::new();
                    if stream.read_to_end(&mut payload).await.is_ok() {
                        stream.write_all(&payload).await.unwrap();
                        stream.shutdown().await.unwrap();
                    }
                });
            }
            result = streams.join_next(), if !streams.is_empty() => { result.unwrap().unwrap(); }
        }
    }
}

struct Exit {
    route: Forwarding,
    connections: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
    _server: Task,
    _certificates: Certificates,
}
impl Exit {
    async fn new(backend: TunnelType) -> Self {
        let certificates = Certificates::new();
        let config = quic::Config {
            addr: "127.0.0.1:0".parse().unwrap(),
            cert: certificates.0.join("cert.pem"),
            priv_key: certificates.0.join("key.pem"),
            transport: Default::default(),
        };
        let (sender, connections) = mpsc::unbounded_channel();
        let (addr, server) = match backend {
            TunnelType::Quinn => {
                let endpoint = quic::quinn::server::new(&config).unwrap();
                let addr = endpoint.local_addr().unwrap();
                let task = tokio::spawn(async move {
                    let mut tasks = tokio::task::JoinSet::new();
                    while let Some(incoming) = endpoint.accept().await {
                        let connection = incoming.await.unwrap();
                        let (close, receiver) = oneshot::channel();
                        sender.send(close).unwrap();
                        let closer = connection.clone();
                        tasks.spawn(serve(connection, receiver, move || {
                            closer.close(0u32.into(), b"test close")
                        }));
                    }
                });
                (addr, task)
            }
            TunnelType::S2nQuic => {
                let mut endpoint = quic::s2n_quic::server::new(&config).unwrap();
                let addr = endpoint.local_addr().unwrap();
                let task = tokio::spawn(async move {
                    let mut tasks = tokio::task::JoinSet::new();
                    while let Some(connection) = endpoint.accept().await {
                        let (handle, acceptor) = connection.split();
                        let (close, receiver) = oneshot::channel();
                        sender.send(close).unwrap();
                        tasks.spawn(serve(acceptor, receiver, move || handle.close(0u32.into())));
                    }
                });
                (addr, task)
            }
            _ => unreachable!(),
        };
        let route = Forwarding::new(Some(&PeerConfig {
            server_addr: addr,
            server_name: "localhost".into(),
            server_cert: config.cert,
            private_key: config.priv_key,
            tunnel_type: backend,
            anytls: None,
            quic: Default::default(),
        }))
        .unwrap();
        Self {
            route,
            connections,
            _server: Task(server),
            _certificates: certificates,
        }
    }
}

fn relay(route: Forwarding) -> (DuplexStream, JoinHandle<io::Result<(u64, u64)>>) {
    let (client, server) = tokio::io::duplex(1024);
    let (recv, send) = tokio::io::split(server);
    (
        client,
        tokio::spawn(async move { handle_routed_forward(send, recv, &route).await }),
    )
}
async fn request(client: &mut DuplexStream, destination: &[u8]) {
    client.write_u8(1).await.unwrap();
    write_string(client, destination).await.unwrap();
}
async fn echo(route: Forwarding, payload: Vec<u8>) {
    let (mut client, task) = relay(route);
    request(&mut client, b"echo.test:80").await;
    assert_eq!(read_string(&mut client).await.unwrap(), BIND);
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, payload);
    task.await.unwrap().unwrap();
}

async fn cache_scenario(backend: TunnelType) {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut exit = Exit::new(backend).await;
        let flows = (0..8).map(|id| echo(exit.route.clone(), vec![id; 128]));
        futures::future::join_all(flows).await;
        let first = exit.connections.recv().await.unwrap();
        assert!(
            exit.connections.try_recv().is_err(),
            "concurrent flows opened multiple QUIC connections"
        );

        let (mut survivor, survivor_task) = relay(exit.route.clone());
        request(&mut survivor, b"echo.test:80").await;
        assert_eq!(read_string(&mut survivor).await.unwrap(), BIND);

        for destination in [
            b"malformed.test:80".as_slice(),
            b"refuse.test:80".as_slice(),
        ] {
            let (mut client, task) = relay(exit.route.clone());
            request(&mut client, destination).await;
            assert!(task.await.unwrap().is_err());
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty(), "failed setup sent a successful bind");
            echo(exit.route.clone(), b"healthy stream after refusal".to_vec()).await;
            assert!(
                exit.connections.try_recv().is_err(),
                "stream failure replaced a healthy connection"
            );
        }

        survivor
            .write_all(b"survived neighboring stream failures")
            .await
            .unwrap();
        survivor.shutdown().await.unwrap();
        let mut survived = Vec::new();
        survivor.read_to_end(&mut survived).await.unwrap();
        assert_eq!(survived, b"survived neighboring stream failures");
        survivor_task.await.unwrap().unwrap();

        let (mut active, task) = relay(exit.route.clone());
        request(&mut active, b"hold.test:80").await;
        assert_eq!(read_string(&mut active).await.unwrap(), BIND);
        first.send(()).unwrap();
        assert!(
            task.await.unwrap().is_err(),
            "closed upstream connection left the relay active"
        );
        echo(exit.route.clone(), b"new connection after close".to_vec()).await;
        let _second = exit.connections.recv().await.unwrap();
        assert!(
            exit.connections.try_recv().is_err(),
            "reconnect opened redundant connections"
        );
    })
    .await
    .expect("QUIC cache scenario exceeded deadline");
}

#[tokio::test]
async fn quinn_relay_reuses_connections_and_recovers_after_close() {
    cache_scenario(TunnelType::Quinn).await;
}
#[tokio::test]
async fn s2n_relay_reuses_connections_and_recovers_after_close() {
    cache_scenario(TunnelType::S2nQuic).await;
}

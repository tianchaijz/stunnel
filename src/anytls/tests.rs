use super::*;
use crate::config::{ClientConfig, ServerConfig};
use crate::tunnel::{
    AsyncReadDatagramExt, AsyncWriteDatagramExt,
    client::{connect_tcp_tunnel, connect_udp_tunnel},
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::time::timeout;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

static IDENTITY: AtomicUsize = AtomicUsize::new(0);

pub(super) struct Fixture {
    pub(super) config: ClientConfig,
    server: tokio::task::JoinHandle<()>,
    state: Arc<Server>,
    directory: PathBuf,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        Self::with_anytls(true).await
    }

    async fn with_anytls(enabled: bool) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "stunnel-anytls-{}-{}",
            std::process::id(),
            IDENTITY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let acceptor = crate::tlstcp::server::tls_acceptor(
            &crate::tlstcp::server::Config {
                addr: listener.local_addr().unwrap(),
                cert: cert_path.clone(),
                priv_key: key_path.clone(),
            },
            enabled,
        )
        .unwrap();
        let config = ClientConfig {
            socks5_listen: "127.0.0.1:0".parse().unwrap(),
            http_listen: "127.0.0.1:0".parse().unwrap(),
            peer: crate::config::PeerConfig {
                server_addr: listener.local_addr().unwrap(),
                server_name: "localhost".into(),
                server_cert: cert_path,
                private_key: key_path,
                tunnel_type: crate::config::TunnelType::AnyTls,
                anytls: Some(crate::config::ClientAnyTlsConfig {
                    password: "test-secret".into(),
                }),
                quic: Default::default(),
            },
            reverse_proxy: vec![],

            #[cfg(target_os = "macos")]
            macos_logging: Default::default(),
        };
        let service = Arc::new(Server::new("test-secret".into()));
        let state = service.clone();
        let server = tokio::spawn(async move {
            crate::tlstcp::server::serve_listener(
                listener,
                acceptor,
                enabled.then_some(service),
                crate::tunnel::upstream::Forwarding::Direct,
            )
            .await
            .unwrap();
        });
        Self {
            config,
            server,
            state,
            directory,
        }
    }
    async fn wait_for_transport_release(&self) {
        timeout(Duration::from_secs(3), async {
            while self.state.slots.available_permits() != MAX_SESSIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("last client owner must release the physical transport");
    }

    fn connector(&self) -> Connector {
        Connector::new(&self.config.peer).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn half_close_target() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                tcp.read_to_end(&mut request).await.unwrap();
                tcp.write_all(b"reply:").await.unwrap();
                tcp.write_all(&request).await.unwrap();
                tcp.shutdown().await.unwrap();
            });
        }
    });
    (address, task)
}

async fn request(connector: Connector, address: std::net::SocketAddr, bytes: &[u8]) -> Vec<u8> {
    timeout(Duration::from_secs(3), async {
        let (_, mut tunnel) = connect_tcp_tunnel(connector, &address.to_string())
            .await
            .unwrap();
        for chunk in bytes.chunks(16 * 1024) {
            tunnel.write_all(chunk).await.unwrap();
        }
        tunnel.shutdown().await.unwrap();
        let mut response = Vec::new();
        tunnel.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .expect("request timed out")
}

#[tokio::test]
async fn half_close_delivers_response_and_reuses_physical_session() {
    let fixture = Fixture::new().await;
    let connector = fixture.connector();
    let (address, target) = half_close_target().await;
    assert_eq!(
        request(connector.clone(), address, b"first").await,
        b"reply:first"
    );
    tokio::task::yield_now().await;
    assert_eq!(
        request(connector.clone(), address, b"second").await,
        b"reply:second"
    );
    assert_eq!(fixture.state.sequence.load(Ordering::SeqCst), 1);
    target.abort();
}

#[tokio::test]
async fn writes_reach_target_without_an_application_flush_or_eof() {
    let fixture = Fixture::new().await;
    let connector = fixture.connector();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut request = [0; 4];
        tcp.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        tcp.write_all(b"pong").await.unwrap();
    });
    timeout(Duration::from_secs(3), async {
        let (_, mut tunnel) = connect_tcp_tunnel(connector.clone(), &address.to_string())
            .await
            .unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        tunnel.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        target.await.unwrap();
    })
    .await
    .expect("accepted output must progress without a caller flush or EOF");
}

#[tokio::test]
async fn server_capacity_follows_both_transport_halves() {
    for read_first in [true, false] {
        let slots = Arc::new(Semaphore::new(1));
        let (stream, mut peer) = tokio::io::duplex(64);
        let transport = OwnedIo {
            stream,
            _owner: slots.clone().acquire_owned().await.unwrap(),
        };
        let (mut reader, mut writer) = tokio::io::split(transport);
        if read_first {
            drop(reader);
            assert_eq!(slots.available_permits(), 0);
            writer.write_all(b"live").await.unwrap();
            let mut received = [0; 4];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"live");
            drop(writer);
        } else {
            drop(writer);
            assert_eq!(slots.available_permits(), 0);
            peer.write_all(b"live").await.unwrap();
            let mut received = [0; 4];
            reader.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"live");
            drop(reader);
        }
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn parallel_flows_are_isolated_with_large_chunked_payloads() {
    let fixture = Fixture::new().await;
    let connector = fixture.connector();
    let (address, target) = half_close_target().await;
    let left = vec![b'a'; 256 * 1024];
    let right = vec![b'b'; 256 * 1024];
    let (a, b) = tokio::join!(
        request(connector.clone(), address, &left),
        request(connector.clone(), address, &right)
    );
    assert_eq!(a, [b"reply:".as_slice(), &left].concat());
    assert_eq!(b, [b"reply:".as_slice(), &right].concat());
    assert_eq!(fixture.state.sequence.load(Ordering::SeqCst), 2);
    target.abort();
}

#[tokio::test]
async fn udp_uses_existing_forward_handler() {
    let fixture = Fixture::new().await;
    let connector = fixture.connector();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 1500];
        let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..len], b"datagram");
        socket.send_to(b"udp reply", peer).await.unwrap();
    });
    timeout(Duration::from_secs(3), async {
        let mut tunnel = connect_udp_tunnel(connector.clone()).await.unwrap();
        tunnel.send_datagram(b"datagram", address).await.unwrap();
        let mut bytes = [0; 1500];
        let (len, from) = tunnel.recv_datagram(&mut bytes).await.unwrap();
        assert_eq!(from, address);
        assert_eq!(&bytes[..len], b"udp reply");
    })
    .await
    .unwrap();
    echo.await.unwrap();
}

#[tokio::test]
async fn authentication_failures_reach_application_io() {
    let fixture = Fixture::new().await;
    let mut config = fixture.config.clone();
    config.peer.anytls.as_mut().unwrap().password = "wrong".into();
    let connector = Connector::new(&config.peer).unwrap();
    let error = timeout(
        Duration::from_secs(3),
        connect_tcp_tunnel(connector.clone(), "127.0.0.1:1"),
    )
    .await
    .unwrap()
    .err()
    .expect("wrong password must fail the forwarding handshake");
    assert!(matches!(
        error.kind(),
        io::ErrorKind::InvalidData
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    ));
    config.peer.server_name = "wrong.example".into();
    let mut connector = Connector::new(&config.peer).unwrap();
    assert!(connector.open_tunnel().await.is_err());
}

#[tokio::test]
async fn cancellation_does_not_replay_bytes() {
    let fixture = Fixture::new().await;
    let mut connector = fixture.connector();
    let mut tunnel = connector.open_tunnel().await.unwrap();
    tunnel.write_all(&[255]).await.unwrap();
    drop(tunnel);
    let (address, target) = half_close_target().await;
    assert_eq!(
        request(connector.clone(), address, b"new").await,
        b"reply:new"
    );
    target.abort();
}

#[test]
fn config_rejects_reverse_and_redacts_password() {
    let config: ClientConfig = toml::from_str(
        r#"
        socks5_listen="127.0.0.1:1080"
        http_listen="127.0.0.1:8080"
        server_addr="127.0.0.1:12346"
        server_name="stunnel"
        server_cert="cert.pem"
        private_key="key.pem"
        tunnel_type="anytls"
        [anytls]
        password="private-secret"
        [quic]
        loss_threshold=0
    "#,
    )
    .unwrap();
    assert!(config.validate().is_ok());
    assert!(!format!("{config:?}").contains("private-secret"));
    let mut reverse = config.clone();
    reverse
        .reverse_proxy
        .push(crate::config::ReverseProxyConfig {
            listen: "127.0.0.1:1".parse().unwrap(),
            target: "127.0.0.1:2".parse().unwrap(),
        });
    assert_eq!(
        reverse.validate().unwrap_err().to_string(),
        "anytls does not support reverse_proxy"
    );
    reverse.reverse_proxy.clear();
    reverse.peer.anytls = None;
    assert_eq!(
        reverse.validate().unwrap_err().to_string(),
        "anytls.password is required"
    );
}

async fn probe_settings(
    fixture: &Fixture,
    connector: tokio_rustls::TlsConnector,
    protocols: Option<Vec<Vec<u8>>>,
) -> io::Result<()> {
    timeout(Duration::from_secs(3), async {
        let tcp = TcpStream::connect(fixture.config.peer.server_addr).await?;
        let name = ServerName::try_from("localhost").unwrap();
        let mut stream = match protocols {
            Some(protocols) => connector.with_alpn(protocols).connect(name, tcp).await?,
            None => connector.connect(name, tcp).await?,
        };
        write_auth(
            &mut stream,
            "test-secret",
            &PaddingFactory::new(DEFAULT_SCHEME).unwrap(),
        )
        .await?;
        let mut settings = anytls_protocol::Frame::new(anytls_protocol::Command::Settings, 0);
        settings.data = b"v=2".to_vec();
        stream.write_all(&settings.encode()?).await?;
        stream.flush().await?;
        anytls_protocol::Frame::read_from(&mut stream).await?;
        Ok(())
    })
    .await
    .expect("TLS policy probe must finish promptly")
}

#[tokio::test]
async fn mutual_tls_requires_a_trusted_client_certificate() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let fixture = Fixture::new().await;
    probe_settings(
        &fixture,
        tls::client(
            &fixture.config.peer.server_cert,
            &fixture.config.peer.private_key,
        )
        .unwrap(),
        None,
    )
    .await
    .unwrap();
    for untrusted in [false, true] {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(&fixture.config.peer.server_cert).unwrap())
            .unwrap();
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
        let mut config = if untrusted {
            let other = Fixture::new().await;
            builder
                .with_client_auth_cert(
                    vec![CertificateDer::from_pem_file(&other.config.peer.server_cert).unwrap()],
                    PrivateKeyDer::from_pem_file(&other.config.peer.private_key).unwrap(),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![tls::ALPN.to_vec()];
        assert!(
            probe_settings(&fixture, Arc::new(config).into(), None)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn unknown_alpn_and_anytls_on_legacy_route_fail() {
    let fixture = Fixture::new().await;
    let connector = tls::client(
        &fixture.config.peer.server_cert,
        &fixture.config.peer.private_key,
    )
    .unwrap();
    for protocols in [vec![], vec![b"other-protocol".to_vec()]] {
        assert!(
            probe_settings(&fixture, connector.clone(), Some(protocols))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn full_client_capacity_rejects_promptly_then_recovers_after_flows_finish() {
    let fixture = Fixture::new().await;
    let mut connector = fixture.connector();
    let mut tunnels = Vec::new();
    for _ in 0..MAX_SESSIONS {
        tunnels.push(connector.open_tunnel().await.unwrap());
    }
    let error = timeout(Duration::from_secs(1), connector.open_tunnel())
        .await
        .expect("capacity rejection must not wait for idle transports to expire")
        .err()
        .expect("all physical transport permits are held");
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    drop(tunnels);
    timeout(Duration::from_secs(3), async {
        loop {
            match connector.open_tunnel().await {
                Ok(tunnel) => break drop(tunnel),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("capacity must recover: {error}"),
            }
        }
    })
    .await
    .expect("finished flows must make capacity available again");
}

#[tokio::test]
async fn cancelled_public_server_closes_authenticated_and_legacy_transports() {
    let mut fixture = Fixture::new().await;
    fixture.server.abort();
    assert!((&mut fixture.server).await.unwrap_err().is_cancelled());
    let config = ServerConfig {
        upstream: None,
        listen: fixture.config.peer.server_addr,
        cert: fixture.config.peer.server_cert.clone(),
        priv_key: fixture.config.peer.private_key.clone(),
        anytls: Some(crate::config::ServerAnyTlsConfig {
            password: "test-secret".into(),
        }),
        quic: Default::default(),
    };
    let listener_task = tokio::spawn(async move { crate::tlstcp::server::serve(&config).await });
    let tcp = timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(tcp) = TcpStream::connect(fixture.config.peer.server_addr).await {
                break tcp;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let connector = tls::client(
        &fixture.config.peer.server_cert,
        &fixture.config.peer.private_key,
    )
    .unwrap();
    let mut stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    write_auth(
        &mut stream,
        "test-secret",
        &PaddingFactory::new(DEFAULT_SCHEME).unwrap(),
    )
    .await
    .unwrap();
    let mut settings = anytls_protocol::Frame::new(anytls_protocol::Command::Settings, 0);
    settings.data = b"v=2".to_vec();
    stream.write_all(&settings.encode().unwrap()).await.unwrap();
    let heart = anytls_protocol::Frame::new(anytls_protocol::Command::HeartRequest, 0)
        .encode()
        .unwrap();
    stream.write_all(&heart).await.unwrap();
    stream.flush().await.unwrap();
    timeout(Duration::from_secs(3), async {
        loop {
            if anytls_protocol::Frame::read_from(&mut stream)
                .await
                .unwrap()
                .command
                == anytls_protocol::Command::HeartResponse
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let mut legacy = tls_connect(&fixture, vec![]).await.unwrap();
    legacy.write_u8(crate::tunnel::TYPE_TCP_FWD).await.unwrap();
    listener_task.abort();
    assert!(listener_task.await.unwrap_err().is_cancelled());
    let closed = timeout(Duration::from_secs(3), legacy.read(&mut [0]))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0) | Err(_)));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = stream.write_all(&heart).await;
    let _ = stream.flush().await;
    let reply = timeout(Duration::from_secs(3), async {
        loop {
            let frame = anytls_protocol::Frame::read_from(&mut stream).await?;
            if frame.command == anytls_protocol::Command::HeartResponse {
                return Ok::<_, io::Error>(frame.command);
            }
        }
    })
    .await;
    assert!(
        matches!(reply, Ok(Err(_))),
        "cancelled listener must close its session, got {reply:?}"
    );
}

#[test]
fn server_owner_releases_session_before_and_after_run_outside_runtime() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for run in [false, true] {
        let slots = Arc::new(Semaphore::new(1));
        let (owner, weak, mut peer) = runtime.block_on(async {
            let (stream, peer) = tokio::io::duplex(64);
            let transport = OwnedIo {
                stream,
                _owner: slots.clone().acquire_owned().await.unwrap(),
            };
            let session = Session::new_server(
                1,
                Box::new(transport),
                Arc::new(RwLock::new(PaddingFactory::new(DEFAULT_SCHEME).unwrap())),
                DEFAULT_MAX_SESSION_AGE,
            );
            let owner = ServerSessionOwner {
                session: Some(session.clone()),
                runtime: Handle::current(),
            };
            if run {
                session.run().await.unwrap();
            }
            (owner, Arc::downgrade(&session), peer)
        });
        assert!(Handle::try_current().is_err());
        drop(owner);
        runtime.block_on(async {
            timeout(Duration::from_secs(3), async {
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                while weak.upgrade().is_some() || slots.available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cancelled owner must release tasks and the transport permit");
        });
    }
}

#[tokio::test]
async fn final_connector_releases_idle_transport_after_clones_are_dropped() {
    let fixture = Fixture::new().await;
    let connector = fixture.connector();
    let clone = connector.clone();
    let (address, target) = half_close_target().await;
    assert_eq!(
        request(connector.clone(), address, b"first").await,
        b"reply:first"
    );
    drop(connector);
    assert_eq!(
        request(clone.clone(), address, b"second").await,
        b"reply:second"
    );
    assert_eq!(fixture.state.sequence.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.slots.available_permits(), MAX_SESSIONS - 1);
    drop(clone);
    fixture.wait_for_transport_release().await;
    target.abort();
}

#[tokio::test]
async fn consumed_connector_keeps_either_returned_half_alive() {
    for keep_reader in [true, false] {
        let fixture = Fixture::new().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (received, delivered) = tokio::sync::oneshot::channel();
        let target = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            tcp.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            tcp.write_all(b"pong").await.unwrap();
            received.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let (_, tunnel) = connect_tcp_tunnel(fixture.connector(), &address.to_string())
            .await
            .unwrap();
        let (mut writer, mut reader) = tunnel.split();
        if keep_reader {
            writer.write_all(b"ping").await.unwrap();
            drop(writer);
            let mut bytes = [0; 4];
            timeout(Duration::from_secs(3), reader.read_exact(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes, b"pong");
            assert_eq!(fixture.state.slots.available_permits(), MAX_SESSIONS - 1);
            drop(reader);
        } else {
            drop(reader);
            timeout(Duration::from_secs(3), writer.write_all(b"ping"))
                .await
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(3), delivered)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(fixture.state.slots.available_permits(), MAX_SESSIONS - 1);
            drop(writer);
        }
        fixture.wait_for_transport_release().await;
        target.abort();
    }
}

#[test]
fn client_and_flow_can_drop_outside_entered_runtime() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (fixture, connector, mut tunnel, target) = runtime.block_on(async {
        let fixture = Fixture::new().await;
        let connector = fixture.connector();
        let (address, target) = half_close_target().await;
        let (_, tunnel) = connect_tcp_tunnel(connector.clone(), &address.to_string())
            .await
            .unwrap();
        (fixture, connector, tunnel, target)
    });
    assert!(Handle::try_current().is_err());
    drop(connector);
    runtime.block_on(async {
        timeout(Duration::from_secs(3), async {
            tunnel.write_all(b"live").await.unwrap();
            tunnel.shutdown().await.unwrap();
            let mut response = Vec::new();
            tunnel.read_to_end(&mut response).await.unwrap();
            assert_eq!(&response, b"reply:live");
        })
        .await
        .unwrap();
        assert_eq!(fixture.state.slots.available_permits(), MAX_SESSIONS - 1);
    });
    drop(tunnel);
    runtime.block_on(fixture.wait_for_transport_release());
    target.abort();
}

#[tokio::test]
async fn failed_forward_open_releases_consumed_client() {
    let fixture = Fixture::new().await;
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = unavailable.local_addr().unwrap();
    drop(unavailable);
    assert!(
        timeout(
            Duration::from_secs(3),
            connect_tcp_tunnel(fixture.connector(), &address.to_string())
        )
        .await
        .unwrap()
        .is_err()
    );
    assert_eq!(fixture.state.sequence.load(Ordering::SeqCst), 1);
    fixture.wait_for_transport_release().await;
}

#[tokio::test]
async fn cancelled_forward_open_releases_consumed_client() {
    let fixture = Fixture::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = fixture.config.clone();
    config.peer.server_addr = listener.local_addr().unwrap();
    let acceptor = test_acceptor(&config.peer.server_cert, &config.peer.private_key);
    let (accepted, ready) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.unwrap();
        read_auth(&mut stream, "test-secret").await.unwrap();
        loop {
            let frame = anytls_protocol::Frame::read_from(&mut stream)
                .await
                .unwrap();
            if frame.command == anytls_protocol::Command::Syn {
                break;
            }
        }
        accepted.send(()).unwrap();
        loop {
            if anytls_protocol::Frame::read_from(&mut stream)
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let opener = Connector::new(&config.peer).unwrap();
    let opening = tokio::spawn(async move { connect_tcp_tunnel(opener, "127.0.0.1:1").await });
    timeout(Duration::from_secs(3), ready)
        .await
        .unwrap()
        .unwrap();
    opening.abort();
    assert!(opening.await.err().unwrap().is_cancelled());
    timeout(Duration::from_secs(3), peer)
        .await
        .expect("cancelled open must close its authenticated connection")
        .unwrap();
}

fn test_acceptor(cert: &std::path::Path, key: &std::path::Path) -> tokio_rustls::TlsAcceptor {
    crate::tlstcp::server::tls_acceptor(
        &crate::tlstcp::server::Config {
            addr: "127.0.0.1:0".parse().unwrap(),
            cert: cert.into(),
            priv_key: key.into(),
        },
        true,
    )
    .unwrap()
}

async fn tls_connect(
    fixture: &Fixture,
    protocols: Vec<Vec<u8>>,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(fixture.config.peer.server_addr).await?;
    tls::client(
        &fixture.config.peer.server_cert,
        &fixture.config.peer.private_key,
    )
    .unwrap()
    .with_alpn(protocols)
    .connect(ServerName::try_from("localhost").unwrap(), tcp)
    .await
}

async fn legacy_flow(
    mut stream: tokio_rustls::client::TlsStream<TcpStream>,
    address: std::net::SocketAddr,
) {
    let address = address.to_string();
    stream.write_u8(crate::tunnel::TYPE_TCP_FWD).await.unwrap();
    stream.write_u8(address.len() as u8).await.unwrap();
    stream.write_all(address.as_bytes()).await.unwrap();
    let length = stream.read_u8().await.unwrap();
    let mut bind = vec![0; length as usize];
    stream.read_exact(&mut bind).await.unwrap();
    std::str::from_utf8(&bind)
        .unwrap()
        .parse::<std::net::SocketAddr>()
        .unwrap();
    stream.write_all(b"legacy").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"reply:legacy");
}

#[tokio::test]
async fn same_port_dispatch_preserves_legacy_without_alpn_and_server_preference() {
    let fixture = Fixture::new().await;
    let (address, target) = half_close_target().await;
    let legacy = async {
        for protocols in [
            vec![],
            vec![b"stunnel".to_vec()],
            vec![ALPN.to_vec(), b"stunnel".to_vec()],
        ] {
            let stream = tls_connect(&fixture, protocols.clone()).await.unwrap();
            let expected = if protocols.is_empty() {
                None
            } else {
                Some(b"stunnel".as_slice())
            };
            assert_eq!(stream.get_ref().1.alpn_protocol(), expected);
            legacy_flow(stream, address).await;
        }
    };
    let anytls = async {
        assert_eq!(
            request(fixture.connector(), address, b"anytls").await,
            b"reply:anytls"
        );
    };
    timeout(Duration::from_secs(3), async {
        tokio::join!(legacy, anytls);
    })
    .await
    .unwrap();
    target.abort();
}

#[tokio::test]
async fn disabled_anytls_keeps_both_legacy_modes_and_rejects_other_alpn() {
    let fixture = Fixture::with_anytls(false).await;
    let (address, target) = half_close_target().await;
    timeout(Duration::from_secs(3), async {
        for protocols in [vec![], vec![b"stunnel".to_vec()]] {
            legacy_flow(tls_connect(&fixture, protocols).await.unwrap(), address).await;
        }
        for protocols in [vec![ALPN.to_vec()], vec![b"unknown".to_vec()]] {
            assert!(tls_connect(&fixture, protocols).await.is_err());
        }
        assert_eq!(fixture.state.slots.available_permits(), MAX_SESSIONS);
    })
    .await
    .unwrap();
    target.abort();
}

#[tokio::test]
async fn full_server_sessions_leave_legacy_admission_available_and_recover() {
    for authenticated in [false, true] {
        let fixture = Fixture::new().await;
        let mut sessions = Vec::new();
        for _ in 0..MAX_SESSIONS {
            let mut stream = tls_connect(&fixture, vec![ALPN.to_vec()]).await.unwrap();
            if authenticated {
                write_auth(
                    &mut stream,
                    "test-secret",
                    &PaddingFactory::new(DEFAULT_SCHEME).unwrap(),
                )
                .await
                .unwrap();
            }
            sessions.push(stream);
        }
        timeout(Duration::from_secs(3), async {
            while fixture.state.slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fixture.state.slots.available_permits(), 0);
        let mut excess = tls_connect(&fixture, vec![ALPN.to_vec()]).await.unwrap();
        let closed = timeout(Duration::from_secs(1), excess.read(&mut [0]))
            .await
            .unwrap();
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "session cap must reject before reading auth"
        );
        let (address, target) = half_close_target().await;
        timeout(
            Duration::from_secs(3),
            legacy_flow(
                tls_connect(&fixture, vec![b"stunnel".to_vec()])
                    .await
                    .unwrap(),
                address,
            ),
        )
        .await
        .unwrap();
        drop(sessions);
        fixture.wait_for_transport_release().await;
        probe_settings(
            &fixture,
            tls::client(
                &fixture.config.peer.server_cert,
                &fixture.config.peer.private_key,
            )
            .unwrap(),
            None,
        )
        .await
        .unwrap();
        target.abort();
    }
}

#[tokio::test]
async fn slow_handshake_slots_reject_excess_and_recover_after_failure_and_timeout() {
    let fixture = Fixture::new().await;
    let mut pending = Vec::new();
    for _ in 0..64 {
        pending.push(
            TcpStream::connect(fixture.config.peer.server_addr)
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fixture.state.slots.available_permits(), MAX_SESSIONS);
    let mut excess = TcpStream::connect(fixture.config.peer.server_addr)
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), excess.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(pending.pop());
    let recovered = timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(stream) = tls_connect(&fixture, vec![]).await {
                break stream;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed handshakes must release admission capacity");
    let (address, target) = half_close_target().await;
    timeout(Duration::from_secs(3), legacy_flow(recovered, address))
        .await
        .unwrap();
    timeout(Duration::from_secs(11), async {
        for mut tcp in pending {
            assert_eq!(tcp.read(&mut [0]).await.unwrap(), 0);
        }
    })
    .await
    .expect("slow TLS admissions must expire");
    timeout(
        Duration::from_secs(3),
        legacy_flow(
            tls_connect(&fixture, vec![b"stunnel".to_vec()])
                .await
                .unwrap(),
            address,
        ),
    )
    .await
    .unwrap();
    target.abort();
}

#[tokio::test]
async fn slow_tls_and_auth_share_one_accept_time_deadline() {
    let fixture = Fixture::new().await;
    let tcp = TcpStream::connect(fixture.config.peer.server_addr)
        .await
        .unwrap();
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(6)).await;
    let mut stream = tls::client(
        &fixture.config.peer.server_cert,
        &fixture.config.peer.private_key,
    )
    .unwrap()
    .connect(ServerName::try_from("localhost").unwrap(), tcp)
    .await
    .unwrap();
    timeout(Duration::from_secs(1), async {
        while fixture.state.slots.available_permits() == MAX_SESSIONS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let closed = timeout(Duration::from_secs(6), stream.read(&mut [0]))
        .await
        .expect("auth must use the remaining four seconds rather than a new ten seconds");
    assert!(matches!(closed, Ok(0) | Err(_)));
    assert!(started.elapsed() >= Duration::from_secs(9));
    assert!(started.elapsed() < Duration::from_secs(12));
    fixture.wait_for_transport_release().await;
    probe_settings(
        &fixture,
        tls::client(
            &fixture.config.peer.server_cert,
            &fixture.config.peer.private_key,
        )
        .unwrap(),
        None,
    )
    .await
    .unwrap();
}

#[test]
fn server_options_reject_obsolete_listener_and_empty_password() {
    let base = "listen='127.0.0.1:12345'\ncert='cert.pem'\npriv_key='key.pem'\n[anytls]\n";
    let parsed: ServerConfig = toml::from_str(&format!("{base}password='secret'\n")).unwrap();
    assert!(parsed.validate().is_ok());
    let stale = toml::from_str::<ServerConfig>(&format!(
        "{base}password='secret'\nlisten='127.0.0.1:12346'\n"
    ))
    .unwrap_err();
    assert!(stale.to_string().contains("unknown field `listen`"));
    let empty: ServerConfig = toml::from_str(&format!("{base}password=''\n")).unwrap();
    assert!(empty.validate().is_err());
}

struct BackpressuredRelay {
    session: Arc<Session>,
    peer: tokio::io::DuplexStream,
    upstream: Arc<crate::tunnel::upstream::Upstream>,
    _permits: Vec<crate::tunnel::upstream::RelayAdmission>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

async fn backpressured_relay() -> BackpressuredRelay {
    use crate::tunnel::upstream::{Forwarding, MAX_RELAY_FLOWS};
    let fixture = Fixture::new().await;
    let Forwarding::Upstream(upstream) = Forwarding::new(Some(&fixture.config.peer)).unwrap()
    else {
        unreachable!()
    };
    let permits = (0..MAX_RELAY_FLOWS - 1)
        .map(|_| upstream.admit().unwrap())
        .collect::<Vec<_>>();
    let (transport, mut peer) = tokio::io::duplex(1);
    let padding = PaddingFactory::new(b"stop=0").unwrap();
    let settings = format!("v=2\npadding-md5={}\n", padding.md5);
    let session = Session::new_server(
        100,
        Box::new(transport),
        Arc::new(RwLock::new(padding)),
        DEFAULT_MAX_SESSION_AGE,
    );
    session.run().await.unwrap();
    let mut frame = anytls_protocol::Frame::new(anytls_protocol::Command::Settings, 0);
    frame.data = settings.into_bytes();
    peer.write_all(&frame.encode().unwrap()).await.unwrap();
    assert_eq!(
        anytls_protocol::Frame::read_from(&mut peer)
            .await
            .unwrap()
            .command,
        anytls_protocol::Command::ServerSettings
    );
    let serving = session.clone();
    let route = Forwarding::Upstream(upstream.clone());
    let task = tokio::spawn(async move { forward_streams(&serving, route).await });
    peer.write_all(
        &anytls_protocol::Frame::new(anytls_protocol::Command::Syn, 1)
            .encode()
            .unwrap(),
    )
    .await
    .unwrap();
    for _ in 0..100 {
        if upstream.admit().is_err() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        upstream.admit().is_err(),
        "SYN must acquire the final relay permit"
    );
    BackpressuredRelay {
        session,
        peer,
        upstream,
        _permits: permits,
        task,
    }
}

#[tokio::test(start_paused = true)]
async fn relay_stalled_synack_releases_admission_at_setup_deadline() {
    let relay = backpressured_relay().await;
    tokio::time::advance(Duration::from_secs(11)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(
        relay.upstream.admit().is_ok(),
        "stalled SynAck must release the relay permit after ten seconds"
    );
    relay.task.abort();
    relay.session.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn relay_header_uses_budget_remaining_after_synack() {
    let mut relay = backpressured_relay().await;
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        anytls_protocol::Frame::read_from(&mut relay.peer)
            .await
            .unwrap()
            .command,
        anytls_protocol::Command::SynAck
    );
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(relay.upstream.admit().is_err());
    tokio::time::advance(Duration::from_secs(5)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(
        relay.upstream.admit().is_ok(),
        "header parsing must not receive a fresh ten-second budget after SynAck"
    );
    relay.task.abort();
    relay.session.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelling_session_during_synack_releases_relay_admission() {
    let relay = backpressured_relay().await;
    relay.task.abort();
    assert!(relay.task.await.unwrap_err().is_cancelled());
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(relay.upstream.admit().is_ok());
    relay.session.shutdown().await.unwrap();
}

#[tokio::test]
async fn public_server_uses_configured_upstream() {
    let exit = Fixture::new().await;
    let mut relay = Fixture::new().await;
    relay.server.abort();
    assert!((&mut relay.server).await.unwrap_err().is_cancelled());
    let config = ServerConfig {
        upstream: Some(exit.config.peer.clone()),
        listen: relay.config.peer.server_addr,
        cert: relay.config.peer.server_cert.clone(),
        priv_key: relay.config.peer.private_key.clone(),
        anytls: Some(crate::config::ServerAnyTlsConfig {
            password: "test-secret".into(),
        }),
        quic: Default::default(),
    };
    relay.server = tokio::spawn(async move {
        crate::tlstcp::server::serve(&config).await.unwrap();
    });
    timeout(Duration::from_secs(3), async {
        loop {
            if TcpStream::connect(relay.config.peer.server_addr)
                .await
                .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (address, target) = half_close_target().await;
    assert_eq!(
        request(relay.connector(), address, b"via upstream").await,
        b"reply:via upstream"
    );
    assert_eq!(exit.state.sequence.load(Ordering::SeqCst), 1);
    target.abort();
}

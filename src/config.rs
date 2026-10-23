use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, de::DeserializeOwned};

use crate::quic::{CongestionControl, QuicConfig};
use crate::telemetry::OtelConfig;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum TunnelType {
    #[serde(rename = "tlstcp")]
    TlsTcp,
    #[serde(rename = "anytls")]
    AnyTls,
    #[serde(rename = "quic")]
    Quinn,
    #[serde(rename = "s2n-quic")]
    S2nQuic,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub enum QuicBackend {
    #[serde(rename = "quic")]
    Quinn,
    #[default]
    #[serde(rename = "s2n-quic")]
    S2nQuic,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReverseProxyConfig {
    pub listen: SocketAddr,
    pub target: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawClientConfig")]
pub struct ClientConfig {
    pub socks5_listen: SocketAddr,
    pub http_listen: SocketAddr,
    pub servers: Vec<PeerConfig>,
    pub otel: OtelConfig,

    #[serde(default)]
    pub reverse_proxy: Vec<ReverseProxyConfig>,

    #[cfg(target_os = "macos")]
    #[serde(default)]
    pub macos_logging: MacOsLogging,
}

#[derive(Deserialize)]
struct RawClientConfig {
    socks5_listen: SocketAddr,
    http_listen: SocketAddr,
    servers: Option<Vec<PeerConfig>>,
    #[serde(default = "client_otel")]
    otel: OtelConfig,
    #[serde(default)]
    reverse_proxy: Vec<ReverseProxyConfig>,
    #[cfg(target_os = "macos")]
    #[serde(default)]
    macos_logging: MacOsLogging,
    #[cfg(not(target_os = "macos"))]
    #[serde(default, rename = "macos_logging")]
    _macos_logging: Option<serde::de::IgnoredAny>,
    #[serde(flatten)]
    legacy: toml::Table,
}

impl TryFrom<RawClientConfig> for ClientConfig {
    type Error = String;
    fn try_from(raw: RawClientConfig) -> Result<Self, Self::Error> {
        let servers = match raw.servers {
            Some(peers) if raw.legacy.is_empty() && !peers.is_empty() => peers,
            Some(_) => {
                return Err(
                    "servers must be nonempty and cannot be mixed with flat peer fields".into(),
                );
            }
            None => vec![
                raw.legacy
                    .try_into()
                    .map_err(|e: toml::de::Error| e.to_string())?,
            ],
        };
        Ok(Self {
            socks5_listen: raw.socks5_listen,
            http_listen: raw.http_listen,
            servers,
            otel: raw.otel,
            reverse_proxy: raw.reverse_proxy,
            #[cfg(target_os = "macos")]
            macos_logging: raw.macos_logging,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub server_cert: PathBuf,
    pub private_key: PathBuf,
    pub tunnel_type: TunnelType,

    pub anytls: Option<ClientAnyTlsConfig>,

    #[serde(default)]
    pub quic: QuicConfig,
}

impl PeerConfig {
    pub fn validate(&self) -> io::Result<()> {
        validate_non_empty(&self.server_name, "server_name")?;
        rustls::pki_types::ServerName::try_from(self.server_name.as_str())
            .map_err(|_| invalid_config("server_name is invalid"))?;
        if matches!(self.tunnel_type, TunnelType::Quinn | TunnelType::S2nQuic) {
            validate_quic(&self.quic)?;
        }
        if self.tunnel_type == TunnelType::AnyTls {
            let anytls = self
                .anytls
                .as_ref()
                .ok_or_else(|| invalid_config("anytls.password is required"))?;
            validate_non_empty(&anytls.password, "anytls.password")?;
        }
        Ok(())
    }
}

impl ClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.servers.is_empty() {
            return Err(invalid_config("servers must not be empty"));
        }
        for peer in &self.servers {
            peer.validate()?;
        }
        if self.servers.len() > 1 && !self.reverse_proxy.is_empty() {
            return Err(invalid_config(
                "multiple servers do not support reverse_proxy",
            ));
        }
        if self.servers[0].tunnel_type == TunnelType::AnyTls && !self.reverse_proxy.is_empty() {
            return Err(invalid_config("anytls does not support reverse_proxy"));
        }

        #[cfg(target_os = "macos")]
        if self.macos_logging.enable {
            validate_non_empty(&self.macos_logging.subsystem, "macos_logging.subsystem")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServerQuicConfig {
    #[serde(default)]
    pub server_type: QuicBackend,
    #[serde(flatten)]
    pub transport: QuicConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawServerConfig")]
pub struct ServerConfig {
    pub upstreams: Vec<PeerConfig>,

    pub listen: SocketAddr,
    pub priv_key: PathBuf,
    pub cert: PathBuf,

    pub anytls: Option<ServerAnyTlsConfig>,

    #[serde(default)]
    pub quic: ServerQuicConfig,

    #[serde(default = "server_otel")]
    pub otel: OtelConfig,
}

#[derive(Deserialize)]
struct RawServerConfig {
    upstream: Option<PeerConfig>,
    upstreams: Option<Vec<PeerConfig>>,
    listen: SocketAddr,
    priv_key: PathBuf,
    cert: PathBuf,
    anytls: Option<ServerAnyTlsConfig>,
    #[serde(default)]
    quic: ServerQuicConfig,
    #[serde(default = "server_otel")]
    otel: OtelConfig,
}

impl TryFrom<RawServerConfig> for ServerConfig {
    type Error = &'static str;
    fn try_from(raw: RawServerConfig) -> Result<Self, Self::Error> {
        let upstreams = match (raw.upstream, raw.upstreams) {
            (Some(_), Some(_)) => return Err("upstream and upstreams cannot be mixed"),
            (None, Some(peers)) if peers.is_empty() => return Err("upstreams must not be empty"),
            (None, Some(peers)) => peers,
            (peer, None) => peer.into_iter().collect(),
        };
        Ok(Self {
            upstreams,
            listen: raw.listen,
            priv_key: raw.priv_key,
            cert: raw.cert,
            anytls: raw.anytls,
            quic: raw.quic,
            otel: raw.otel,
        })
    }
}

impl ServerConfig {
    pub fn validate(&self) -> io::Result<()> {
        if let Some(anytls) = &self.anytls {
            validate_non_empty(&anytls.password, "anytls.password")?;
        }
        for peer in &self.upstreams {
            peer.validate()?;
            let listen = self.listen;
            let target = peer.server_addr;
            let listen_ip = listen.ip().to_canonical();
            let target_ip = target.ip().to_canonical();
            if listen.port() == target.port()
                && (listen_ip == target_ip
                    || (listen_ip.is_unspecified()
                        && (listen_ip.is_ipv6() || target_ip.is_ipv4())
                        && (target_ip.is_loopback() || target_ip.is_unspecified())))
            {
                return Err(invalid_config("upstream points to this server's listener"));
            }
        }
        validate_quic(&self.quic.transport)
    }
}

#[derive(Clone, Deserialize)]
pub struct ClientAnyTlsConfig {
    pub password: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerAnyTlsConfig {
    pub password: String,
}

impl std::fmt::Debug for ClientAnyTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAnyTlsConfig")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for ServerAnyTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerAnyTlsConfig")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default, Clone, Deserialize)]
pub struct MacOsLogging {
    pub enable: bool,
    pub subsystem: String,
}

pub fn load_client(path: impl AsRef<Path>) -> io::Result<ClientConfig> {
    let path = path.as_ref();
    let config = read_toml::<ClientConfig>(path)?;
    config.validate()?;
    Ok(config)
}

pub fn load_server(path: impl AsRef<Path>) -> io::Result<ServerConfig> {
    let path = path.as_ref();
    let config = read_toml::<ServerConfig>(path)?;
    config.validate()?;
    Ok(config)
}

fn read_toml<T>(path: &Path) -> io::Result<T>
where
    T: DeserializeOwned,
{
    let content = fs::read_to_string(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read config {}: {error}", path.display()),
        )
    })?;

    toml::from_str(&content).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse config {}: {error}", path.display()),
        )
    })
}

fn validate_quic(config: &QuicConfig) -> io::Result<()> {
    if config.loss_threshold == 0 {
        return Err(invalid_config("quic.loss_threshold must be greater than 0"));
    }

    if config.cc == CongestionControl::Fixed && config.fixed_bandwidth == 0 {
        return Err(invalid_config(
            "quic.fixed_bandwidth must be greater than 0 when cc is fixed",
        ));
    }

    Ok(())
}

fn validate_non_empty(value: &str, field: &str) -> io::Result<()> {
    if value.trim().is_empty() {
        Err(invalid_config(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn invalid_config(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

// The two binaries report under their own service name, so one dashboard can
// be read against either end without editing the config.
fn client_otel() -> OtelConfig {
    OtelConfig::for_service("stunnel-client")
}

fn server_otel() -> OtelConfig {
    OtelConfig::for_service("stunnel-server")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_defaults_are_applied() {
        let config: QuicConfig = toml::from_str("").unwrap();

        assert_eq!(config.cc, CongestionControl::Bbr);
        assert_eq!(config.loss_threshold, 20);
        assert_eq!(config.fixed_bandwidth, 6 * 1024 * 1024);
    }

    #[test]
    fn server_quic_config_keeps_legacy_flattened_fields() {
        let config: ServerQuicConfig = toml::from_str(
            r#"
                server_type = "quic"
                cc = "fixed"
                loss_threshold = 10
                fixed_bandwidth = 1024
            "#,
        )
        .unwrap();

        assert_eq!(config.server_type, QuicBackend::Quinn);
        assert_eq!(config.transport.cc, CongestionControl::Fixed);
        assert_eq!(config.transport.loss_threshold, 10);
        assert_eq!(config.transport.fixed_bandwidth, 1024);
    }

    #[test]
    fn tls_tcp_ignores_quic_and_reverse_proxy_config() {
        let config = ClientConfig {
            otel: client_otel(),
            socks5_listen: "127.0.0.1:1080".parse().unwrap(),
            http_listen: "127.0.0.1:8080".parse().unwrap(),
            servers: vec![crate::config::PeerConfig {
                server_addr: "127.0.0.1:12345".parse().unwrap(),
                server_name: "stunnel".to_string(),
                server_cert: PathBuf::new(),
                private_key: PathBuf::new(),
                tunnel_type: TunnelType::TlsTcp,
                anytls: None,
                quic: QuicConfig {
                    cc: CongestionControl::Fixed,
                    loss_threshold: 0,
                    fixed_bandwidth: 0,
                },
            }],
            reverse_proxy: vec![ReverseProxyConfig {
                listen: "127.0.0.1:8081".parse().unwrap(),
                target: "127.0.0.1:3000".parse().unwrap(),
            }],

            #[cfg(target_os = "macos")]
            macos_logging: MacOsLogging::default(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn each_binary_defaults_to_its_own_service_name() {
        let client: ClientConfig = toml::from_str(
            r#"
                socks5_listen = "127.0.0.1:1080"
                http_listen = "127.0.0.1:8080"
                server_addr = "127.0.0.1:12345"
                server_name = "stunnel"
                server_cert = "cert.pem"
                private_key = "key.pem"
                tunnel_type = "tlstcp"
            "#,
        )
        .unwrap();
        assert_eq!(client.otel.service_name, "stunnel-client");

        let server: ServerConfig = toml::from_str(
            r#"
                listen = "127.0.0.1:12345"
                priv_key = "key.pem"
                cert = "cert.pem"
            "#,
        )
        .unwrap();
        assert_eq!(server.otel.service_name, "stunnel-server");

        // A config that names the service wins over the default.
        let client: ClientConfig = toml::from_str(
            r#"
                socks5_listen = "127.0.0.1:1080"
                http_listen = "127.0.0.1:8080"
                server_addr = "127.0.0.1:12345"
                server_name = "stunnel"
                server_cert = "cert.pem"
                private_key = "key.pem"
                tunnel_type = "tlstcp"
                otel = { endpoint = "http://127.0.0.1:4318", service_name = "stunnel-a" }
            "#,
        )
        .unwrap();
        assert_eq!(client.otel.service_name, "stunnel-a");
        assert_eq!(
            client.otel.resolved_endpoint().as_deref(),
            Some("http://127.0.0.1:4318")
        );
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    const SERVER: &str = "listen='127.0.0.1:443'\npriv_key='key.pem'\ncert='cert.pem'\n";
    const PEER: &str = "server_addr='127.0.0.1:444'\nserver_name='exit'\nserver_cert='exit.pem'\nprivate_key='exit.key'\ntunnel_type='tlstcp'\n";

    #[test]
    fn existing_client_tables_remain_flattened() {
        let client: ClientConfig = toml::from_str(&format!("socks5_listen='127.0.0.1:1080'\nhttp_listen='127.0.0.1:8080'\n{PEER}\n[quic]\ncc='bbr'\n")).unwrap();
        assert_eq!(client.servers[0].server_name, "exit");
        assert!(client.validate().is_ok());
    }

    #[test]
    fn upstream_rejects_listener_and_reverse_fields() {
        for field in [
            "socks5_listen='127.0.0.1:1080'",
            "http_listen='127.0.0.1:8080'",
            "reverse_proxy=[]",
            "listen='127.0.0.1:444'",
            "typo=true",
        ] {
            assert!(
                toml::from_str::<ServerConfig>(&format!("{SERVER}[upstream]\n{PEER}{field}\n"))
                    .is_err(),
                "accepted {field}"
            );
        }
    }

    #[test]
    fn obvious_self_loops_are_rejected_but_remote_same_port_is_valid() {
        for (listen, target, valid) in [
            ("127.0.0.1:443", "127.0.0.1:443", false),
            ("0.0.0.0:443", "127.0.0.1:443", false),
            ("[::]:443", "[::1]:443", false),
            ("[::]:443", "127.0.0.1:443", false),
            ("[::]:443", "[::ffff:127.0.0.1]:443", false),
            ("0.0.0.0:443", "[::ffff:127.0.0.1]:443", false),
            ("127.0.0.1:443", "[::ffff:127.0.0.1]:443", false),
            ("[::]:443", "192.0.2.1:443", true),
            ("0.0.0.0:443", "192.0.2.1:443", true),
        ] {
            for transport in ["tlstcp", "anytls", "quic", "s2n-quic"] {
                let text = format!(
                    "{}[anytls]\npassword='inbound-secret'\n[upstream]\n{}\n[upstream.anytls]\npassword='outbound-secret'\n",
                    SERVER.replace("127.0.0.1:443", listen),
                    PEER.replace("127.0.0.1:444", target)
                        .replace("tlstcp", transport)
                );
                assert_eq!(
                    toml::from_str::<ServerConfig>(&text)
                        .unwrap()
                        .validate()
                        .is_ok(),
                    valid,
                    "listen {listen}, upstream {target}, transport {transport}"
                );
            }
        }
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;
    const CLIENT: &str = "socks5_listen='127.0.0.1:1080'\nhttp_listen='127.0.0.1:8080'\n";
    const SERVER: &str = "listen='127.0.0.1:443'\npriv_key='key.pem'\ncert='cert.pem'\n";
    const PEER: &str = "server_addr='127.0.0.1:444'\nserver_name='exit'\nserver_cert='exit.pem'\nprivate_key='exit.key'\ntunnel_type='quic'\n";

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn legacy_client_ignores_macos_logging() {
        for value in ["{enable=false}", "{enable=true}", "['ignored', 42]"] {
            let text = format!("{CLIENT}macos_logging={value}\n{PEER}");
            let client: ClientConfig = toml::from_str(&text).unwrap();
            client.validate().unwrap();
            assert_eq!(client.servers.len(), 1);
            assert_eq!(client.servers[0].server_name, "exit");
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn list_client_ignores_macos_logging() {
        for value in ["{enable=false}", "{enable=true}", "['ignored', 42]"] {
            let text = format!("{CLIENT}macos_logging={value}\n[[servers]]\n{PEER}");
            let client: ClientConfig = toml::from_str(&text).unwrap();
            client.validate().unwrap();
            assert_eq!(client.servers.len(), 1);
            assert_eq!(client.servers[0].server_name, "exit");
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn ignored_macos_logging_does_not_hide_unknown_peer_fields() {
        for prefix in ["", "[[servers]]\n"] {
            let text = format!(
                "{CLIENT}macos_logging={{enable=false}}\n{prefix}{PEER}server_nmae='typo'\n"
            );
            let error = toml::from_str::<ClientConfig>(&text).unwrap_err();
            assert!(error.to_string().contains("unknown field `server_nmae`"));
        }
    }

    #[test]
    fn otel_is_process_config_for_flat_and_list_peers() {
        for prefix in ["", "[[servers]]\n"] {
            let text = format!(
                "{CLIENT}otel={{endpoint='http://localhost:4318',service_name='edge'}}\n{prefix}{PEER}"
            );
            let client: ClientConfig = toml::from_str(&text).unwrap();
            assert_eq!(client.otel.service_name, "edge");
            assert_eq!(
                client.otel.endpoint.as_deref(),
                Some("http://localhost:4318")
            );
            assert_eq!(client.servers.len(), 1);
            assert!(
                toml::from_str::<ClientConfig>(&format!("{text}server_nmae='typo'\n")).is_err()
            );
        }
        for upstream in ["", "[upstream]\n", "[[upstreams]]\n"] {
            let peers = if upstream.is_empty() {
                String::new()
            } else {
                format!("{upstream}{PEER}")
            };
            let server: ServerConfig =
                toml::from_str(&format!("{SERVER}otel={{service_name='relay'}}\n{peers}")).unwrap();
            assert_eq!(server.otel.service_name, "relay");
        }
    }

    #[test]
    fn lists_preserve_order_and_single_entry_compatibility() {
        for count in [1, 2] {
            let peers = (0..count)
                .map(|i| {
                    format!(
                        "[[servers]]\n{}",
                        PEER.replace("444", &(444 + i).to_string())
                    )
                })
                .collect::<String>();
            let client: ClientConfig = toml::from_str(&format!("{CLIENT}{peers}")).unwrap();
            client.validate().unwrap();
            assert_eq!(client.servers.len(), count as usize);
            assert_eq!(
                client.servers.last().unwrap().server_addr.port(),
                443 + count
            );
            let server: ServerConfig = toml::from_str(&format!(
                "{SERVER}{}",
                peers.replace("servers", "upstreams")
            ))
            .unwrap();
            server.validate().unwrap();
            assert_eq!(server.upstreams.len(), count as usize);
        }
        let direct: ServerConfig = toml::from_str(SERVER).unwrap();
        assert!(direct.upstreams.is_empty());
    }

    #[test]
    fn empty_mixed_and_incomplete_forms_are_rejected() {
        for text in [
            format!("{CLIENT}servers=[]\n"),
            format!("{CLIENT}{PEER}[[servers]]\n{PEER}"),
            format!("{CLIENT}server_name='partial'\n[[servers]]\n{PEER}"),
            format!("{CLIENT}[[servers]]\n{PEER}[[servers]]\nserver_name='incomplete'\n"),
        ] {
            assert!(toml::from_str::<ClientConfig>(&text).is_err());
        }
        for text in [
            format!("{SERVER}upstreams=[]\n"),
            format!("{SERVER}[upstream]\n{PEER}[[upstreams]]\n{PEER}"),
            format!("{SERVER}[upstream]\nserver_name='partial'\n[[upstreams]]\n{PEER}"),
            format!("{SERVER}[[upstreams]]\n{PEER}[[upstreams]]\nserver_name='incomplete'\n"),
        ] {
            assert!(toml::from_str::<ServerConfig>(&text).is_err());
        }
    }

    #[test]
    fn invalid_backup_options_authentication_and_self_loops_are_rejected() {
        for backup in [
            format!("{PEER}[servers.quic]\nloss_threshold=0\n"),
            PEER.replace("quic", "anytls"),
            format!(
                "{}[servers.anytls]\npassword=''\n",
                PEER.replace("quic", "anytls")
            ),
        ] {
            let client: ClientConfig =
                toml::from_str(&format!("{CLIENT}[[servers]]\n{PEER}[[servers]]\n{backup}"))
                    .unwrap();
            assert!(client.validate().is_err());
        }
        let server: ServerConfig = toml::from_str(&format!(
            "{SERVER}[[upstreams]]\n{PEER}[[upstreams]]\n{}",
            PEER.replace("444", "443")
        ))
        .unwrap();
        assert!(server.validate().is_err());
        assert!(
            toml::from_str::<ClientConfig>(&format!(
                "{CLIENT}[[servers]]\n{PEER}[[servers]]\n{PEER}typo=true\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn multiple_reverse_peers_are_rejected_but_single_list_is_supported() {
        let reverse = "reverse_proxy=[{listen='127.0.0.1:5000',target='127.0.0.1:5001'}]\n";
        let mut client: ClientConfig =
            toml::from_str(&format!("{CLIENT}{reverse}[[servers]]\n{PEER}")).unwrap();
        client.validate().unwrap();
        client.servers.push(client.servers[0].clone());
        assert!(client.validate().is_err());
    }
}

use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, de::DeserializeOwned};

use crate::quic::{CongestionControl, QuicConfig};

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
pub struct ClientConfig {
    pub socks5_listen: SocketAddr,
    pub http_listen: SocketAddr,
    #[serde(flatten)]
    pub peer: PeerConfig,

    #[serde(default)]
    pub reverse_proxy: Vec<ReverseProxyConfig>,

    #[cfg(target_os = "macos")]
    #[serde(default)]
    pub macos_logging: MacOsLogging,
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
        self.peer.validate()?;
        if self.peer.tunnel_type == TunnelType::AnyTls && !self.reverse_proxy.is_empty() {
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
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub priv_key: PathBuf,
    pub cert: PathBuf,

    pub anytls: Option<ServerAnyTlsConfig>,

    #[serde(default)]
    pub quic: ServerQuicConfig,
}

impl ServerConfig {
    pub fn validate(&self) -> io::Result<()> {
        if let Some(anytls) = &self.anytls {
            validate_non_empty(&anytls.password, "anytls.password")?;
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
            socks5_listen: "127.0.0.1:1080".parse().unwrap(),
            http_listen: "127.0.0.1:8080".parse().unwrap(),
            peer: crate::config::PeerConfig {
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
            },
            reverse_proxy: vec![ReverseProxyConfig {
                listen: "127.0.0.1:8081".parse().unwrap(),
                target: "127.0.0.1:3000".parse().unwrap(),
            }],

            #[cfg(target_os = "macos")]
            macos_logging: MacOsLogging::default(),
        };

        assert!(config.validate().is_ok());
    }
}

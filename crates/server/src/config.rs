//! Server config file (`server.toml`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer, de};
use transport::QuicConfig;

use crate::egress::Cidr;

/// Whole config file. Sections for later features (`masquerade`, `metrics`) are accepted and
/// read by the code that needs them.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// `[server]`.
    pub server: ServerSection,
    /// `[tls]`.
    pub tls: TlsSection,
    /// `[limits]`.
    #[serde(default)]
    pub limits: Limits,
    /// `[egress]`.
    #[serde(default)]
    pub egress: EgressSection,
    /// `[quic]`.
    #[serde(default)]
    pub quic: QuicConfig,
    /// `[resolver]`.
    #[serde(default)]
    pub resolver: ResolverSection,
    /// `[bench]`.
    #[serde(default)]
    pub bench: BenchSection,
}

/// `[bench]`: endpoints for `partizan bench`; off by default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BenchSection {
    /// Serve `partizan.bench` to authenticated devices.
    pub enabled: bool,
}

/// `[server]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Server domain: certificate name and default SNI.
    pub domain: Option<String>,
    /// Address for UDP/443 and TCP/443.
    pub listen: SocketAddr,
    /// Auth path, part of every connection URI.
    pub auth_path: String,
    /// Device registry file.
    pub devices: PathBuf,
    /// Admin socket.
    pub admin_sock: Option<PathBuf>,
}

/// Certificate source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// Let's Encrypt for the domain.
    Acme,
    /// Let's Encrypt certificate for the IP.
    AcmeIp,
    /// PEM files.
    Files,
    /// Generated at start; only usable with a pin.
    SelfSigned,
}

/// `[tls]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    /// Certificate source.
    pub mode: TlsMode,
    /// Certificate chain (PEM), for `files`.
    pub cert: Option<PathBuf>,
    /// Private key (PEM), for `files`.
    pub key: Option<PathBuf>,
}

/// `[limits]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Concurrent sessions per device; over it the oldest is closed.
    pub sessions_per_device: u32,
    /// Concurrent UDP sessions per device.
    pub udp_sessions_per_device: u32,
    /// UDP session idle timeout.
    #[serde(deserialize_with = "duration")]
    pub udp_idle_timeout: Duration,
    /// Idle timeout for UDP sessions to port 53: DNS answers once.
    #[serde(deserialize_with = "duration")]
    pub udp_dns_idle_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions_per_device: 2,
            udp_sessions_per_device: 512,
            udp_idle_timeout: Duration::from_secs(60),
            udp_dns_idle_timeout: Duration::from_secs(10),
        }
    }
}

/// `[egress]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EgressSection {
    /// Refuse loopback, private, link-local, CGNAT and cloud metadata addresses.
    pub deny_private: bool,
    /// Exceptions to the deny list.
    pub allow: Vec<Cidr>,
}

impl Default for EgressSection {
    fn default() -> Self {
        Self {
            deny_private: true,
            allow: Vec::new(),
        }
    }
}

/// `[resolver]`: system resolver tuning.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResolverSection {
    /// Per-query timeout.
    #[serde(deserialize_with = "duration")]
    pub timeout: Duration,
    /// Attempts per name server.
    pub attempts: usize,
}

impl Default for ResolverSection {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            attempts: 2,
        }
    }
}

fn duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    transport::parse_duration(&s).ok_or_else(|| de::Error::custom(format!("bad duration {s:?}")))
}

impl Config {
    /// Reads and parses a config file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example_parses() {
        let text = r#"
            [server]
            domain     = "cdn.example.com"
            listen     = "[::]:443"
            auth_path  = "/api/v2/sync"
            devices    = "/etc/vpn/devices.toml"
            admin_sock = "/run/vpn/admin.sock"

            [tls]
            mode = "acme"

            [masquerade]
            mode = "static"
            dir  = "/var/www/site"

            [limits]
            sessions_per_device = 2
            udp_sessions_per_device = 512
            udp_idle_timeout = "60s"

            [egress]
            deny_private = true
            allow = []

            [quic]
            congestion = "cubic"
            stream_receive_window = "4MiB"
            receive_window = "16MiB"

            [metrics]
            listen = "127.0.0.1:9090"
        "#;
        let config: Config = toml::from_str(text).unwrap();
        assert_eq!(config.tls.mode, TlsMode::Acme);
        assert_eq!(config.limits.udp_idle_timeout, Duration::from_secs(60));
        assert!(config.egress.deny_private);
        assert_eq!(config.quic.stream_receive_window, 4 << 20);
    }
}

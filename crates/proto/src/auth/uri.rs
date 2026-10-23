//! Connection URI: everything a client needs to reach the server, in one line.
//!
//! `partizan://<device_id>:<token>@<host>[:<port>]?path=<auth_path>[&sni=..][&pin=sha256/..]
//! [&transport=auto|quic|tls][&insecure=1][&pbk=..&sid=..]`

use std::fmt::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};

use zeroize::Zeroizing;

use super::encoding::{base64url, hex, percent_decode, percent_encode, unbase64url, unhex};
use super::secret::{DeviceId, Token};

const SCHEME: &str = "partizan://";
const DEFAULT_PORT: u16 = 443;
const MAX_PATH: usize = 1024;

/// Malformed connection URI; names the offending part, never the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid connection URI: {0}")]
pub struct UriError(pub &'static str);

/// Which transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    /// QUIC first, TCP+TLS on failure.
    #[default]
    Auto,
    /// QUIC only.
    Quic,
    /// TCP+TLS only.
    Tls,
}

impl TransportMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Quic => "quic",
            Self::Tls => "tls",
        }
    }
}

/// Passthrough masquerade parameters (REALITY-style mark in ClientHello).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Passthrough {
    /// Server's static X25519 public key (`pbk`).
    pub public_key: [u8; 32],
    /// This device's short id (`sid`).
    pub short_id: [u8; 8],
}

/// Parsed connection URI.
#[derive(Clone)]
pub struct ConnectionUri {
    /// Device id.
    pub device_id: DeviceId,
    /// Device token.
    pub token: Token,
    /// Server host: domain, IPv4 or IPv6 (without brackets).
    pub host: String,
    /// Server port.
    pub port: u16,
    /// TLS server name if it differs from `host`.
    pub sni: Option<String>,
    /// Auth path.
    pub path: String,
    /// SHA-256 of the server certificate's SPKI.
    pub pin: Option<[u8; 32]>,
    /// Transport choice; always [`TransportMode::Tls`] with passthrough.
    pub transport: TransportMode,
    /// Skip certificate checks (tests only).
    pub insecure: bool,
    /// Passthrough masquerade parameters.
    pub passthrough: Option<Passthrough>,
}

impl fmt::Debug for ConnectionUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionUri")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("sni", &self.sni)
            .field("path", &self.path)
            .field("pin", &self.pin.map(|p| hex(&p)))
            .field("transport", &self.transport)
            .field("insecure", &self.insecure)
            .field("passthrough", &self.passthrough)
            .finish()
    }
}

/// Pin as written in a URI and in logs: `sha256/<base64url>`.
pub fn format_pin(pin: &[u8; 32]) -> String {
    format!("sha256/{}", base64url(pin))
}

/// Parses the base64url part of a pin (after `sha256/`).
pub fn parse_pin_base64(s: &str) -> Option<[u8; 32]> {
    unbase64url(s)
}

impl ConnectionUri {
    /// TLS server name: `sni`, else `host`.
    pub fn server_name(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }

    /// HTTP authority: server name, plus the port when it is not 443.
    pub fn authority(&self) -> String {
        let name = self.server_name();
        let name = if name.contains(':') {
            format!("[{name}]")
        } else {
            name.to_owned()
        };
        if self.port == DEFAULT_PORT {
            name
        } else {
            format!("{name}:{}", self.port)
        }
    }

    /// Formats the URI; it contains the token, hence `Zeroizing`.
    pub fn to_uri_string(&self) -> Zeroizing<String> {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let path = percent_encode(&self.path);
        let token = self.token.to_base64url();
        // Sized up front so growing never leaves a copy of the token behind; the optional
        // parameters take at most 200 bytes besides `sni`.
        let len = SCHEME.len()
            + 32
            + 1
            + token.len()
            + 1
            + host.len()
            + 6
            + 6
            + path.len()
            + self.sni.as_ref().map_or(0, |s| s.len() + 5)
            + 200;
        let mut s = Zeroizing::new(String::with_capacity(len));
        let _ = write!(
            s,
            "{SCHEME}{}:{}@{host}:{}?path={path}",
            self.device_id,
            token.as_str(),
            self.port
        );
        if let Some(sni) = &self.sni {
            let _ = write!(s, "&sni={sni}");
        }
        if let Some(pin) = &self.pin {
            let _ = write!(s, "&pin={}", format_pin(pin));
        }
        if self.transport != TransportMode::Auto {
            let _ = write!(s, "&transport={}", self.transport.as_str());
        }
        if self.insecure {
            s.push_str("&insecure=1");
        }
        if let Some(p) = &self.passthrough {
            let _ = write!(
                s,
                "&pbk={}&sid={}",
                base64url(&p.public_key),
                hex(&p.short_id)
            );
        }
        debug_assert!(s.len() <= len, "capacity estimate too small");
        s
    }

    /// Parses a URI. Unknown parameters are ignored so older clients accept newer links.
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let rest = s.strip_prefix(SCHEME).ok_or(UriError("scheme"))?;
        let (authority, query) = rest.split_once('?').ok_or(UriError("missing query"))?;
        let (userinfo, hostport) = authority.split_once('@').ok_or(UriError("credentials"))?;
        let (id, token) = userinfo.split_once(':').ok_or(UriError("credentials"))?;
        let device_id = DeviceId::from_hex(id).ok_or(UriError("device id"))?;
        let token = Token::from_base64url(token).ok_or(UriError("token"))?;
        let (host, port) = parse_hostport(hostport)?;

        let mut uri = Self {
            device_id,
            token,
            host,
            port,
            sni: None,
            path: String::new(),
            pin: None,
            transport: TransportMode::Auto,
            insecure: false,
            passthrough: None,
        };
        let (mut seen, mut pbk, mut sid) = (Vec::new(), None, None);
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').ok_or(UriError("query"))?;
            if seen.contains(&key) {
                return Err(UriError("duplicate parameter"));
            }
            seen.push(key);
            let value = percent_decode(value).ok_or(UriError("percent-encoding"))?;
            match key {
                "path" => {
                    let valid = value.starts_with('/')
                        && value.len() <= MAX_PATH
                        && value.bytes().all(|b| b.is_ascii_graphic() && b != b'#');
                    if !valid {
                        return Err(UriError("path"));
                    }
                    uri.path = value;
                }
                "sni" if is_domain(&value) => uri.sni = Some(value),
                "sni" => return Err(UriError("sni")),
                "pin" => {
                    let pin = value.strip_prefix("sha256/").and_then(unbase64url);
                    uri.pin = Some(pin.ok_or(UriError("pin"))?);
                }
                "transport" => {
                    uri.transport = match value.as_str() {
                        "auto" => TransportMode::Auto,
                        "quic" => TransportMode::Quic,
                        "tls" => TransportMode::Tls,
                        _ => return Err(UriError("transport")),
                    }
                }
                "insecure" => {
                    uri.insecure = match value.as_str() {
                        "1" => true,
                        "0" => false,
                        _ => return Err(UriError("insecure")),
                    }
                }
                "pbk" => pbk = Some(unbase64url(&value).ok_or(UriError("pbk"))?),
                "sid" => sid = Some(unhex(&value).ok_or(UriError("sid"))?),
                _ => {}
            }
        }
        if uri.path.is_empty() {
            return Err(UriError("missing path"));
        }
        match (pbk, sid) {
            (Some(public_key), Some(short_id)) => {
                // QUIC has no room for the mark, so passthrough is TCP+TLS only.
                if uri.transport == TransportMode::Quic {
                    return Err(UriError("passthrough needs transport=tls"));
                }
                uri.transport = TransportMode::Tls;
                uri.passthrough = Some(Passthrough {
                    public_key,
                    short_id,
                });
            }
            (None, None) => {}
            _ => return Err(UriError("pbk and sid go together")),
        }
        Ok(uri)
    }
}

fn parse_hostport(s: &str) -> Result<(String, u16), UriError> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (v6, after) = rest.split_once(']').ok_or(UriError("host"))?;
        v6.parse::<Ipv6Addr>().map_err(|_| UriError("host"))?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(UriError("host"))?),
        };
        (v6, port)
    } else {
        match s.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (s, None),
        }
    };
    if !host.contains(':') && host.parse::<Ipv4Addr>().is_err() && !is_domain(host) {
        return Err(UriError("host"));
    }
    let port = match port {
        None if !s.ends_with(':') => DEFAULT_PORT,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse().ok().filter(|&p| p != 0).ok_or(UriError("port"))?
        }
        _ => return Err(UriError("port")),
    };
    Ok((host.to_owned(), port))
}

fn is_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnectionUri {
        ConnectionUri {
            device_id: DeviceId([0x11; 16]),
            token: Token::from_bytes([0x22; 32]),
            host: "cdn.example.com".into(),
            port: 443,
            sni: None,
            path: "/api/v2/sync".into(),
            pin: Some([0x33; 32]),
            transport: TransportMode::Auto,
            insecure: false,
            passthrough: None,
        }
    }

    fn same(a: &ConnectionUri, b: &ConnectionUri) -> bool {
        format!("{a:?}") == format!("{b:?}") && a.token.hash().matches(&b.token.hash())
    }

    #[test]
    fn c05_t6_uri_roundtrips_with_pin_and_transport() {
        let uri = sample();
        let s = uri.to_uri_string();
        let parsed = ConnectionUri::parse(&s).unwrap();
        assert!(same(&parsed, &uri));
        assert_eq!(parsed.pin, Some([0x33; 32]));
        assert_eq!(parsed.transport, TransportMode::Auto);

        let mut v6 = sample();
        v6.host = "2001:db8::1".into();
        v6.port = 8443;
        v6.sni = Some("cdn.example.com".into());
        v6.transport = TransportMode::Quic;
        v6.insecure = true;
        let parsed = ConnectionUri::parse(&v6.to_uri_string()).unwrap();
        assert!(same(&parsed, &v6));
        assert_eq!(parsed.authority(), "cdn.example.com:8443");

        let mut pt = sample();
        pt.transport = TransportMode::Tls;
        pt.sni = Some("www.example.org".into());
        pt.passthrough = Some(Passthrough {
            public_key: [0x44; 32],
            short_id: [0x55; 8],
        });
        assert!(same(
            &ConnectionUri::parse(&pt.to_uri_string()).unwrap(),
            &pt
        ));
    }

    #[test]
    fn spec_example_parses() {
        let token = base64url(&[7; 32]);
        let pin = base64url(&[9; 32]);
        let s = format!(
            "partizan://{}:{token}@cdn.example.com?path=/api/v2/sync&pin=sha256/{pin}&transport=tls&future=x",
            "ab".repeat(16)
        );
        let uri = ConnectionUri::parse(&s).unwrap();
        assert_eq!(uri.port, 443, "default port");
        assert_eq!(uri.transport, TransportMode::Tls);
        assert_eq!(uri.server_name(), "cdn.example.com");
        assert_eq!(uri.authority(), "cdn.example.com");
        // Passthrough forces TLS.
        let s = format!("{s}&pbk={}&sid={}", base64url(&[1; 32]), "01".repeat(8))
            .replace("&transport=tls", "");
        assert_eq!(
            ConnectionUri::parse(&s).unwrap().transport,
            TransportMode::Tls
        );
    }

    #[test]
    fn bad_uris_are_rejected() {
        let good = sample().to_uri_string();
        let token = sample().token.to_base64url();
        let cases = [
            good.replace("partizan://", "https://"),
            good.replace(token.as_str(), "short"),
            good.replace("1111", "11"),
            good.replace("cdn.example.com", "-bad-.com"),
            good.replace(":443", ":0"),
            good.replace(":443", ":99999"),
            good.replace(":443", ":"),
            good.replace("path=/api/v2/sync", "path=api"),
            good.replace("path=/api/v2/sync", "x=1"),
            format!("{}&transport=udp", good.as_str()),
            format!("{}&path=/again", good.as_str()),
            format!("{}&pbk={}", good.as_str(), base64url(&[1; 32])),
            format!(
                "{}&transport=quic&pbk={}&sid={}",
                good.as_str(),
                base64url(&[1; 32]),
                "01".repeat(8)
            ),
            good.replace("sha256/", "sha1/"),
            good.replace("cdn.example.com:443", "[::1]junk"),
            format!("{}&insecure=yes", good.as_str()),
        ];
        for s in &cases {
            assert!(ConnectionUri::parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn c05_t8_uri_debug_and_errors_hide_the_token() {
        let uri = sample();
        let shown = format!("{uri:?}");
        assert!(!shown.contains(uri.token.to_base64url().as_str()));
        assert!(shown.contains("<redacted>"));
        let bad = uri.to_uri_string().replace(":443", ":0");
        let err = ConnectionUri::parse(&bad).unwrap_err().to_string();
        assert!(!err.contains(uri.token.to_base64url().as_str()));
    }
}

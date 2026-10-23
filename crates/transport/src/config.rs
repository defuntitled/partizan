//! QUIC parameters, shared by the client and server configs (`[quic]` section).

use std::time::Duration;

use serde::{Deserialize, Deserializer, de};

/// Congestion controller. quinn's BBR is experimental and deliberately not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Congestion {
    /// CUBIC (RFC 9438), quinn's default.
    #[default]
    Cubic,
    /// NewReno (RFC 6582).
    NewReno,
}

/// QUIC tuning; defaults are the starting values from the spec, refined by benchmarks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
    /// Congestion controller.
    pub congestion: Congestion,
    /// Per-stream receive window: BDP for ~300 Mbit/s at 100 ms RTT.
    #[serde(deserialize_with = "size")]
    pub stream_receive_window: u64,
    /// Connection-wide receive window.
    #[serde(deserialize_with = "size")]
    pub receive_window: u64,
    /// Connection-wide send window.
    #[serde(deserialize_with = "size")]
    pub send_window: u64,
    /// Streams the peer may open at once.
    pub max_concurrent_bidi_streams: u32,
    /// Outgoing datagram buffer; beyond it old datagrams are dropped, not delayed.
    #[serde(deserialize_with = "size")]
    pub datagram_send_buffer: u64,
    /// Idle timeout.
    #[serde(deserialize_with = "duration")]
    pub idle_timeout: Duration,
    /// Keepalive interval, to hold provider NAT mappings.
    #[serde(deserialize_with = "duration")]
    pub keep_alive: Duration,
    /// MTU before path MTU discovery.
    pub initial_mtu: u16,
    /// Upper bound for path MTU discovery.
    pub max_mtu: u16,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            congestion: Congestion::Cubic,
            stream_receive_window: 4 << 20,
            receive_window: 16 << 20,
            send_window: 16 << 20,
            max_concurrent_bidi_streams: 1024,
            datagram_send_buffer: 64 << 10,
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(10),
            initial_mtu: 1200,
            max_mtu: 1452,
        }
    }
}

/// Size as an integer or a string with a binary suffix: `4MiB`, `64KiB`, `1500`.
fn size<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Int(u64),
        Text(String),
    }
    match Raw::deserialize(d)? {
        Raw::Int(n) => Ok(n),
        Raw::Text(s) => parse_size(&s).ok_or_else(|| de::Error::custom(format!("bad size {s:?}"))),
    }
}

fn parse_size(s: &str) -> Option<u64> {
    let (digits, mult) = [
        ("GiB", 1u64 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("", 1),
    ]
    .into_iter()
    .find_map(|(suffix, mult)| s.strip_suffix(suffix).map(|d| (d, mult)))?;
    let valid = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    valid
        .then(|| digits.parse::<u64>().ok()?.checked_mul(mult))
        .flatten()
}

/// Duration string: `30s`, `500ms`, `5m`.
fn duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    parse_duration(&s).ok_or_else(|| de::Error::custom(format!("bad duration {s:?}")))
}

/// Parses `500ms`, `30s` or `5m`; shared with the binaries' configs.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let (digits, unit): (&str, fn(u64) -> Duration) = if let Some(d) = s.strip_suffix("ms") {
        (d, Duration::from_millis)
    } else if let Some(d) = s.strip_suffix('s') {
        (d, Duration::from_secs)
    } else {
        (s.strip_suffix('m')?, |m| {
            Duration::from_secs(m.saturating_mul(60))
        })
    };
    let valid = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    valid.then(|| digits.parse().ok().map(unit)).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_durations_parse() {
        assert_eq!(parse_size("4MiB"), Some(4 << 20));
        assert_eq!(parse_size("64KiB"), Some(64 << 10));
        assert_eq!(parse_size("1500"), Some(1500));
        for bad in ["", "MiB", "4 MiB", "4mb", "-1", "99999999999GiB"] {
            assert_eq!(parse_size(bad), None, "{bad}");
        }
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        for bad in ["", "s", "10", "1h", "1.5s"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }
}

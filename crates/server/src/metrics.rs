//! Prometheus metrics: counters kept in atomics, gauges read from the live state at scrape
//! time, served as text on a loopback HTTP endpoint (`[metrics] listen`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use proto::auth::AuthFailure;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::State;

/// Bucket bounds in seconds for both histograms.
const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

/// A cumulative histogram over [`BUCKETS`].
#[derive(Debug, Default)]
pub struct Histogram {
    counts: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    /// Records one observation.
    pub fn observe(&self, value: Duration) {
        let secs = value.as_secs_f64();
        for (bound, count) in BUCKETS.iter().zip(&self.counts) {
            if secs <= *bound {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add(value.as_micros() as u64, Ordering::Relaxed);
    }

    fn render(&self, name: &str, out: &mut String) {
        out.push_str(&format!("# TYPE {name} histogram\n"));
        for (bound, count) in BUCKETS.iter().zip(&self.counts) {
            out.push_str(&format!(
                "{name}_bucket{{le=\"{bound}\"}} {}\n",
                count.load(Ordering::Relaxed)
            ));
        }
        let count = self.count.load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
        out.push_str(&format!("{name}_sum {sum}\n{name}_count {count}\n"));
    }
}

/// Auth outcomes, in label order.
const AUTH_RESULTS: [&str; 7] = [
    "ok",
    "malformed",
    "wrong_path",
    "unknown_device",
    "bad_token",
    "revoked",
    "unsupported_version",
];
/// Stream outcomes, in label order.
pub const STREAM_RESULTS: [&str; 6] = [
    "ok",
    "not_allowed",
    "unreachable",
    "refused",
    "timeout",
    "protocol_error",
];

/// Counters.
#[derive(Debug, Default)]
pub struct Metrics {
    /// UDP replies larger than the client's datagram limit.
    pub udp_oversize_drops: AtomicU64,
    /// Undecodable datagrams, or a new UDP session without a destination.
    pub udp_malformed_drops: AtomicU64,
    /// Datagrams to destinations the egress policy refuses.
    pub udp_denied_drops: AtomicU64,
    /// QUIC and TCP connections accepted (authenticated or not).
    pub connections: AtomicU64,
    auth: [AtomicU64; AUTH_RESULTS.len()],
    streams: [AtomicU64; STREAM_RESULTS.len()],
    /// Streams being proxied now.
    pub streams_active: AtomicU64,
    /// Bytes of sessions that already ended: [quic up, quic down, tls up, tls down].
    closed_bytes: [AtomicU64; 4],
    /// Time to connect to a target.
    pub dial_duration: Histogram,
}

impl Metrics {
    /// Current value of a counter.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Counts an auth attempt.
    pub fn auth<T>(&self, result: &Result<T, AuthFailure>) {
        let i = match result {
            Ok(_) => 0,
            Err(AuthFailure::Malformed) => 1,
            Err(AuthFailure::WrongPath) => 2,
            Err(AuthFailure::UnknownDevice) => 3,
            Err(AuthFailure::BadToken) => 4,
            Err(AuthFailure::Revoked) => 5,
            Err(AuthFailure::UnsupportedVersion) => 6,
        };
        self.auth[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a finished stream by its outcome, an index into [`STREAM_RESULTS`].
    pub fn stream(&self, result: usize) {
        self.streams[result.min(STREAM_RESULTS.len() - 1)].fetch_add(1, Ordering::Relaxed);
    }

    /// Adds the traffic of a session that ended.
    pub fn session_closed(&self, transport: &str, sent: u64, received: u64) {
        let base = if transport == "tls" { 2 } else { 0 };
        // From the server's side: received is upload from the device, sent is download.
        self.closed_bytes[base].fetch_add(received, Ordering::Relaxed);
        self.closed_bytes[base + 1].fetch_add(sent, Ordering::Relaxed);
    }
}

/// The whole exposition.
pub fn render(state: &State) -> String {
    let m = &state.metrics;
    let sessions = state.sessions.list();
    let mut out = String::new();
    out.push_str("# TYPE sessions_active gauge\n");
    for kind in ["quic", "tls"] {
        let n = sessions.iter().filter(|(_, s)| s.transport == kind).count();
        out.push_str(&format!("sessions_active{{transport=\"{kind}\"}} {n}\n"));
    }
    out.push_str("# TYPE auth_total counter\n");
    for (label, count) in AUTH_RESULTS.iter().zip(&m.auth) {
        out.push_str(&format!(
            "auth_total{{result=\"{label}\"}} {}\n",
            count.load(Ordering::Relaxed)
        ));
    }
    out.push_str(&format!(
        "# TYPE streams_active gauge\nstreams_active {}\n",
        m.streams_active.load(Ordering::Relaxed)
    ));
    out.push_str("# TYPE streams_total counter\n");
    for (label, count) in STREAM_RESULTS.iter().zip(&m.streams) {
        out.push_str(&format!(
            "streams_total{{status=\"{label}\"}} {}\n",
            count.load(Ordering::Relaxed)
        ));
    }
    out.push_str(&format!(
        "# TYPE udp_sessions_active gauge\nudp_sessions_active {}\n",
        state.udp_sessions_active()
    ));
    out.push_str("# TYPE bytes_total counter\n");
    for (i, kind) in ["quic", "tls"].iter().enumerate() {
        let (mut up, mut down) = (
            m.closed_bytes[i * 2].load(Ordering::Relaxed),
            m.closed_bytes[i * 2 + 1].load(Ordering::Relaxed),
        );
        for (_, s) in sessions.iter().filter(|(_, s)| s.transport == *kind) {
            let stats = s.connection.stats();
            up += stats.bytes_received;
            down += stats.bytes_sent;
        }
        out.push_str(&format!(
            "bytes_total{{dir=\"up\",transport=\"{kind}\"}} {up}\n"
        ));
        out.push_str(&format!(
            "bytes_total{{dir=\"down\",transport=\"{kind}\"}} {down}\n"
        ));
    }
    out.push_str("# TYPE datagram_drops_total counter\n");
    for (label, counter) in [
        ("oversize", &m.udp_oversize_drops),
        ("malformed", &m.udp_malformed_drops),
        ("denied", &m.udp_denied_drops),
    ] {
        out.push_str(&format!(
            "datagram_drops_total{{reason=\"{label}\"}} {}\n",
            counter.load(Ordering::Relaxed)
        ));
    }
    m.dial_duration.render("dial_duration_seconds", &mut out);
    // RTT of the live sessions, as a histogram built at scrape time.
    let rtts = Histogram::default();
    for (_, s) in &sessions {
        let rtt = s.connection.stats().rtt;
        if !rtt.is_zero() {
            rtts.observe(rtt);
        }
    }
    rtts.render("rtt_seconds", &mut out);
    out
}

/// Serves `GET /metrics` on `listener` until it fails.
pub async fn serve(listener: TcpListener, state: Arc<State>) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            else {
                return;
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let response = if request.starts_with("GET /metrics ") {
                let body = render(&state);
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
            } else {
                "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".into()
            };
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Binds the metrics endpoint.
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

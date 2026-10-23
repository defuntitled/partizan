//! Operations: metrics, graceful shutdown, and logs that keep secrets out.

mod common;

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::*;
use proto::auth::{DataFrameReader, HandshakeError, Token};
use proto::control::ControlReader;
use proto::{ConnectStatus, ControlFrame, ErrorCode, Host, TargetAddr};
use server::Server;
use server::config::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport::Transport;

/// Everything the server logs at INFO and above in this test binary.
fn logs() -> &'static Arc<Mutex<Vec<u8>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = buf.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || Capture(writer.clone()))
            .init();
        buf
    })
}

struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Running {
    addr: SocketAddr,
    pin: [u8; 32],
    metrics: SocketAddr,
    state: Arc<server::State>,
    shutdown: server::Shutdown,
}

async fn start() -> Running {
    logs();
    let devices = temp_path("devices.toml");
    write_registry(&devices, false);
    let dir = devices.parent().unwrap();
    let config = dir.join("server.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndomain = \"localhost\"\nlisten = \"127.0.0.1:0\"\nauth_path = \"/api/v2/sync\"\n\
             devices = \"{}\"\n[tls]\nmode = \"self-signed\"\n[egress]\nallow = [\"127.0.0.0/8\"]\n\
             [metrics]\nlisten = \"127.0.0.1:0\"\n",
            devices.display()
        ),
    )
    .unwrap();
    let server = Server::bind(Config::load(&config).unwrap()).await.unwrap();
    let running = Running {
        addr: server.local_addr().unwrap(),
        pin: server.pin(),
        metrics: server.metrics_addr().unwrap(),
        state: server.state(),
        shutdown: server.shutdown_handle(),
    };
    tokio::spawn(server.run());
    running
}

async fn scrape(addr: SocketAddr) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

fn value(metrics: &str, series: &str) -> Option<f64> {
    metrics
        .lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

#[tokio::test(flavor = "multi_thread")]
async fn c20_t1_metrics_count_sessions_streams_bytes_and_drops() {
    let r = start().await;
    assert_eq!(
        connect(r.addr, r.pin, [0; 32]).await.err(),
        Some(HandshakeError::Rejected)
    );
    let client = connect(r.addr, r.pin, TOKEN).await.unwrap();
    let echo = echo_server().await;
    let (mut send, mut recv) = open(&client, ip_target(echo), b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    send.write_all(b"ping").await.unwrap();
    send.shutdown().await.unwrap();
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let m = scrape(r.metrics).await;
    assert!(m.starts_with("HTTP/1.1 200 OK"), "{m}");
    assert_eq!(
        value(&m, "sessions_active{transport=\"quic\"}"),
        Some(1.0),
        "{m}"
    );
    assert_eq!(value(&m, "auth_total{result=\"ok\"}"), Some(1.0));
    assert_eq!(value(&m, "auth_total{result=\"bad_token\"}"), Some(1.0));
    assert_eq!(value(&m, "streams_total{status=\"ok\"}"), Some(1.0));
    assert_eq!(value(&m, "streams_active"), Some(0.0));
    assert_eq!(value(&m, "dial_duration_seconds_count"), Some(1.0));
    assert_eq!(value(&m, "rtt_seconds_count"), Some(1.0));
    assert!(value(&m, "bytes_total{dir=\"up\",transport=\"quic\"}").unwrap() > 0.0);
    assert!(m.contains("datagram_drops_total{reason=\"oversize\"}"));
    assert!(m.contains("udp_sessions_active"));
    // Only /metrics is served there.
    let mut s = tokio::net::TcpStream::connect(r.metrics).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut other = String::new();
    s.read_to_string(&mut other).await.unwrap();
    assert!(other.starts_with("HTTP/1.1 404"));
}

#[tokio::test(flavor = "multi_thread")]
async fn c20_t2_sigterm_sends_go_away_refuses_new_sessions_and_drains_streams() {
    let r = start().await;
    let mut client = connect(r.addr, r.pin, TOKEN).await.unwrap();
    let echo = echo_server().await;
    let (mut send, mut recv) = open(&client, ip_target(echo), b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));

    let shutdown = tokio::spawn(async move {
        let started = Instant::now();
        r.shutdown
            .run(Duration::from_secs(10), Duration::from_secs(3))
            .await;
        started.elapsed()
    });
    // GoAway with the retry delay arrives on the control channel.
    let (mut data, mut frames) = (DataFrameReader::default(), ControlReader::default());
    let go_away = client
        .next_control(&mut data, &mut frames, Duration::from_secs(2))
        .await;
    assert_eq!(
        go_away,
        Some(ControlFrame::GoAway {
            code: ErrorCode::SERVER_SHUTDOWN,
            retry_after_ms: 3000
        })
    );
    // No new sessions while draining.
    let refused = tokio::time::timeout(Duration::from_secs(4), connect(r.addr, r.pin, TOKEN)).await;
    assert!(
        !matches!(refused, Ok(Ok(_))),
        "a new session was accepted during shutdown"
    );
    // The open stream keeps working, then ends; the drain stops as soon as it is gone.
    send.write_all(b"still here").await.unwrap();
    let mut buf = [0u8; 10];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still here");
    send.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let _ = recv.read_to_end(&mut rest).await;
    let took = tokio::time::timeout(Duration::from_secs(12), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert!(
        took < Duration::from_secs(9),
        "drain did not stop when streams ended: {took:?}"
    );
    assert!(
        r.state.sessions.is_empty()
            || tokio::time::timeout(Duration::from_secs(2), client.transport.closed())
                .await
                .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn c20_t3_tokens_and_destinations_stay_out_of_info_logs() {
    let r = start().await;
    let client = connect(r.addr, r.pin, TOKEN).await.unwrap();
    let echo = echo_server().await;
    let (_send, mut recv) = open(
        &client,
        TargetAddr {
            host: Host::V4(Ipv4Addr::LOCALHOST),
            port: echo.port(),
        },
        b"",
    )
    .await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let _ = connect(r.addr, r.pin, [7; 32]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let text = String::from_utf8_lossy(&logs().lock().unwrap()).into_owned();
    assert!(
        text.contains("session started"),
        "nothing logged at info:\n{text}"
    );
    for secret in [
        Token::from_bytes(TOKEN).to_base64url(),
        Token::from_bytes([7; 32]).to_base64url(),
    ] {
        assert!(!text.contains(secret.as_str()), "token in the logs");
    }
    assert!(
        !text.contains(&format!("127.0.0.1:{}", echo.port())),
        "destination in the info logs:\n{text}"
    );
    assert!(
        !text.contains(&format!("port: {}", echo.port())),
        "destination in the info logs:\n{text}"
    );
}

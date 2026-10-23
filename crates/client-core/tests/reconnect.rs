//! Session supervision against a real server: restarts, GoAway, waiting for a session.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use client_core::{ConnectError, Engine, EngineConfig, EngineError};
use proto::auth::{ClientInfo, ConnectionUri, DeviceId, Token, TransportMode};
use proto::{ErrorCode, Host, TargetAddr};
use server::Server;
use server::config::{
    Config, EgressSection, Limits, ResolverSection, ServerSection, TlsMode, TlsSection,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use transport::QuicConfig;

const ID: DeviceId = DeviceId([4; 16]);
const TOKEN: [u8; 32] = [6; 32];

struct Fixture {
    dir: PathBuf,
    pin: [u8; 32],
}

/// Certificate files and a registry, shared by every server start so the pin stays.
fn fixture() -> Fixture {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "partizan-reconnect-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    let hash = Token::from_bytes(TOKEN).hash().to_hex();
    std::fs::write(
        dir.join("devices.toml"),
        format!("[[device]]\nid = \"{ID}\"\nname = \"r\"\ntoken_sha256 = \"{hash}\"\n"),
    )
    .unwrap();
    let pin = transport::tls::spki_pin(cert.der()).unwrap();
    Fixture { dir, pin }
}

async fn start_server(
    f: &Fixture,
    listen: SocketAddr,
) -> (SocketAddr, Arc<server::State>, quinn::Endpoint) {
    let config = Config {
        server: ServerSection {
            domain: None,
            listen,
            auth_path: "/sync".into(),
            devices: f.dir.join("devices.toml"),
            admin_sock: None,
        },
        tls: TlsSection {
            mode: TlsMode::Files,
            cert: Some(f.dir.join("cert.pem")),
            key: Some(f.dir.join("key.pem")),
        },
        limits: Limits::default(),
        egress: EgressSection {
            deny_private: true,
            allow: vec!["127.0.0.0/8".parse().unwrap()],
        },
        quic: QuicConfig::default(),
        resolver: ResolverSection::default(),
    };
    // A restart on the same port waits until the old endpoint's last handle lets go.
    let deadline = Instant::now() + Duration::from_secs(3);
    let server = loop {
        match Server::bind(config.clone()).await {
            Ok(server) => break server,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("server bind: {e}"),
        }
    };
    let addr = server.local_addr().unwrap();
    let (state, endpoint) = (server.state(), server.endpoint());
    tokio::spawn(server.run());
    (addr, state, endpoint)
}

async fn stop_server(endpoint: quinn::Endpoint) {
    endpoint.close(0u32.into(), b"restart");
    endpoint.wait_idle().await;
}

fn engine(f: &Fixture, addr: SocketAddr) -> Engine {
    let uri = ConnectionUri {
        device_id: ID,
        token: Token::from_bytes(TOKEN),
        host: "127.0.0.1".into(),
        port: addr.port(),
        sni: Some("localhost".into()),
        path: "/sync".into(),
        pin: Some(f.pin),
        transport: TransportMode::Quic,
        insecure: false,
        passthrough: None,
    };
    Engine::new(EngineConfig {
        uri,
        quic: QuicConfig::default(),
        info: ClientInfo::new("test", "0.1.0"),
    })
}

fn target(addr: SocketAddr) -> TargetAddr {
    TargetAddr {
        host: Host::V4(Ipv4Addr::LOCALHOST),
        port: addr.port(),
    }
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// Polls `f` until it is true or `timeout` passes.
async fn eventually(timeout: Duration, mut f: impl AsyncFnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn c14_t1_server_restart_reconnects_breaks_tcp_and_keeps_udp() {
    let f = fixture();
    let (addr, _, endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;
    let (echo, uecho) = (tcp_echo().await, udp_echo().await);
    let engine = engine(&f, addr);
    engine.start();
    let (mut send, mut recv) = engine.open_tcp(target(echo), true).await.unwrap();
    send.write_all(b"before").await.unwrap();
    let mut buf = [0u8; 6];
    recv.read_exact(&mut buf).await.unwrap();
    let mut flow = engine.open_udp();
    flow.send(target(uecho), Bytes::from_static(b"udp before"))
        .await
        .unwrap();
    assert_eq!(
        &tokio::time::timeout(Duration::from_secs(2), flow.recv())
            .await
            .unwrap()
            .unwrap()
            .payload[..],
        b"udp before"
    );

    stop_server(endpoint).await;
    let (_, state, _endpoint) = start_server(&f, addr).await;

    // The open TCP stream does not survive the restart.
    let mut rest = Vec::new();
    let broken = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(&mut rest)).await;
    assert!(
        matches!(broken, Ok(Err(_)) | Ok(Ok(0))),
        "stream survived: {broken:?}"
    );

    // The engine reconnects by itself and new streams work.
    assert!(
        eventually(Duration::from_secs(15), async || engine
            .open_tcp(target(echo), true)
            .await
            .is_ok())
        .await,
        "no reconnect"
    );
    assert_eq!(state.sessions.len(), 1);
    assert!(engine.status().await.reconnects >= 1);

    // The UDP flow carries on: its next datagram names the destination again.
    flow.send(target(uecho), Bytes::from_static(b"udp after"))
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), flow.recv())
        .await
        .expect("UDP reply after reconnect")
        .unwrap();
    assert_eq!(&reply.payload[..], b"udp after");
}

#[tokio::test(flavor = "multi_thread")]
async fn c14_t2_go_away_revoked_stops_reconnecting() {
    let f = fixture();
    let (addr, state, _endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;
    let engine = engine(&f, addr);
    engine.start();
    assert!(eventually(Duration::from_secs(5), async || state.sessions.len() == 1).await);
    assert_eq!(state.sessions.go_away(None, ErrorCode::REVOKED, 0), 1);
    assert!(
        eventually(Duration::from_secs(5), async || {
            matches!(
                engine.open_tcp(target(addr), true).await,
                Err(ConnectError::Session(EngineError::Revoked))
            )
        })
        .await
    );
    assert!(engine.status().await.revoked);
    // No new connection attempts afterwards.
    let before = state.metrics.connections.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(state.metrics.connections.load(Ordering::Relaxed), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn c14_t3_go_away_shutdown_retries_after_the_delay() {
    let f = fixture();
    let (addr, state, _endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;
    let engine = engine(&f, addr);
    engine.start();
    assert!(eventually(Duration::from_secs(5), async || state.sessions.len() == 1).await);
    let before = state.metrics.connections.load(Ordering::Relaxed);
    let sent = Instant::now();
    state
        .sessions
        .go_away(None, ErrorCode::SERVER_SHUTDOWN, 800);
    assert!(
        eventually(Duration::from_secs(5), async || state
            .metrics
            .connections
            .load(Ordering::Relaxed)
            > before)
        .await
    );
    let waited = sent.elapsed();
    assert!(
        waited >= Duration::from_millis(750),
        "reconnected after {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(3),
        "reconnected after {waited:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn c14_t5_connect_waits_up_to_five_seconds_for_a_session() {
    let f = fixture();
    let (addr, _, endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;
    let echo = tcp_echo().await;
    let engine = engine(&f, addr);
    engine.start();
    engine.open_tcp(target(echo), true).await.unwrap();

    // Server gone for good: the request fails after the wait (SOCKS answers REP 0x01).
    stop_server(endpoint).await;
    let started = Instant::now();
    let result = engine.open_tcp(target(echo), true).await;
    let waited = started.elapsed();
    let err = result.err().expect("no session, no stream");
    assert_eq!(err, ConnectError::Session(EngineError::Unavailable));
    assert_eq!(err.socks_reply(), 0x01);
    assert!(
        waited >= Duration::from_millis(4900) && waited < Duration::from_secs(7),
        "waited {waited:?}"
    );

    // Server back within the wait: the pending request goes through.
    let pending = tokio::spawn({
        let engine = engine.clone();
        async move { engine.open_tcp(target(echo), true).await.map(|_| ()) }
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _server = start_server(&f, addr).await;
    assert_eq!(pending.await.unwrap(), Ok(()));
}

#[tokio::test(flavor = "multi_thread")]
async fn rebind_keeps_the_session() {
    let f = fixture();
    let (addr, state, _endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;
    let echo = tcp_echo().await;
    let engine = engine(&f, addr);
    engine.start();
    engine.open_tcp(target(echo), true).await.unwrap();
    engine.rebind().unwrap();
    let (mut send, mut recv) = engine.open_tcp(target(echo), true).await.unwrap();
    send.write_all(b"migrated").await.unwrap();
    let mut buf = [0u8; 8];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"migrated");
    assert_eq!(
        engine.status().await.reconnects,
        0,
        "same session after rebind"
    );
    assert_eq!(state.sessions.len(), 1);
}

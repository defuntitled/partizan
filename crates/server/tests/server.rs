//! Server end to end in one process: a test client authenticates over QUIC and proxies TCP.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use proto::auth::{
    ClientHandshake, ClientInfo, ConnectionUri, DeviceId, HandshakeError, Token,
    Transport as AuthTransport, TransportMode, client_control_stream,
};
use proto::{Connect, ConnectResult, ConnectStatus, ErrorCode, Host, TargetAddr};
use server::Server;
use server::config::{
    Config, EgressSection, Limits, ResolverSection, ServerSection, TlsMode, TlsSection,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use transport::quic::{self, QuicTransport};
use transport::tls::{self, ALPN_H3, ServerVerification};
use transport::{QuicConfig, RecvHalf, SendHalf, Transport};

const ID: DeviceId = DeviceId([7; 16]);
const TOKEN: [u8; 32] = [9; 32];

fn temp_path(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "partizan-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn write_registry(path: &PathBuf, revoked: bool) {
    let hash = Token::from_bytes(TOKEN).hash().to_hex();
    let text = format!(
        "[[device]]\nid = \"{ID}\"\nname = \"router\"\ntoken_sha256 = \"{hash}\"\nrevoked = {revoked}\n"
    );
    std::fs::write(path, text).unwrap();
}

/// Server on loopback; `allow_loopback` lets it dial local test targets.
async fn start(
    allow_loopback: bool,
) -> (SocketAddr, [u8; 32], std::sync::Arc<server::State>, PathBuf) {
    let devices = temp_path("devices.toml");
    write_registry(&devices, false);
    let config = Config {
        server: ServerSection {
            domain: Some("localhost".into()),
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_path: "/api/v2/sync".into(),
            devices: devices.clone(),
            admin_sock: None,
        },
        tls: TlsSection {
            mode: TlsMode::SelfSigned,
            cert: None,
            key: None,
        },
        limits: Limits::default(),
        egress: EgressSection {
            deny_private: true,
            allow: if allow_loopback {
                vec!["127.0.0.0/8".parse().unwrap()]
            } else {
                Vec::new()
            },
        },
        quic: QuicConfig::default(),
        resolver: ResolverSection {
            timeout: Duration::from_millis(500),
            attempts: 1,
        },
    };
    let server = Server::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap();
    let pin = server.pin();
    let state = server.state();
    tokio::spawn(server.run());
    (addr, pin, state, devices)
}

fn uri(token: [u8; 32]) -> ConnectionUri {
    ConnectionUri {
        device_id: ID,
        token: Token::from_bytes(token),
        host: "localhost".into(),
        port: 443,
        sni: None,
        path: "/api/v2/sync".into(),
        pin: None,
        transport: TransportMode::Quic,
        insecure: false,
        passthrough: None,
    }
}

/// Test client: connects, opens the HTTP/3 control stream and authenticates.
struct Client {
    transport: QuicTransport,
    _control: (quinn::SendStream, quinn::SendStream, quinn::RecvStream),
}

async fn connect(
    addr: SocketAddr,
    pin: [u8; 32],
    token: [u8; 32],
) -> Result<Client, HandshakeError> {
    let tls = tls::client_config(ServerVerification::Pin(pin), &[ALPN_H3]).unwrap();
    let endpoint =
        quic::client_endpoint("127.0.0.1:0".parse().unwrap(), tls, &QuicConfig::default()).unwrap();
    let transport = quic::connect(&endpoint, addr, "localhost").await.unwrap();
    let conn = transport.connection().clone();
    let mut h3_control = conn.open_uni().await.unwrap();
    h3_control
        .write_all(&client_control_stream())
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let info = ClientInfo::new("test", "0.1.0");
    let (mut handshake, request) =
        ClientHandshake::start(AuthTransport::Quic, &uri(token), &info, Instant::now()).unwrap();
    send.write_all(&request).await.unwrap();
    let mut buf = [0u8; 4096];
    loop {
        let n = recv.read(&mut buf).await.unwrap().unwrap_or(0);
        if n == 0 {
            return Err(HandshakeError::Rejected);
        }
        if handshake.handle_input(&buf[..n])?.is_some() {
            break;
        }
    }
    std::mem::forget(endpoint); // Keep the socket alive for the test.
    Ok(Client {
        transport,
        _control: (h3_control, send, recv),
    })
}

/// Opens a stream with `Connect` (plus `early` bytes in the same write).
async fn open(client: &Client, target: TargetAddr, early: &[u8]) -> (SendHalf, RecvHalf) {
    let (mut send, recv) = client.transport.open_stream().await.unwrap();
    let mut header = Vec::new();
    Connect {
        addr: target,
        padding: 0,
    }
    .encode(&mut header)
    .unwrap();
    header.extend_from_slice(early);
    send.write_all(&header).await.unwrap();
    (send, recv)
}

/// Reads the `ConnectResult`; `Err(code)` if the stream was reset instead.
async fn read_result(recv: &mut RecvHalf) -> Result<ConnectStatus, ErrorCode> {
    let mut buf = Vec::new();
    loop {
        if let Ok((result, used)) = ConnectResult::decode(&buf) {
            assert_eq!(used, buf.len(), "test reads the result alone");
            return Ok(result.status);
        }
        let mut byte = [0u8; 1];
        match recv.read(&mut byte).await {
            Ok(1) => buf.push(byte[0]),
            Ok(_) => panic!("stream ended before ConnectResult"),
            Err(e) => return Err(reset_code(&e).expect("reset with a code")),
        }
    }
}

fn reset_code(e: &std::io::Error) -> Option<ErrorCode> {
    match e.get_ref()?.downcast_ref::<quinn::ReadError>()? {
        quinn::ReadError::Reset(code) => Some(ErrorCode(code.into_inner())),
        _ => None,
    }
}

async fn echo_server() -> SocketAddr {
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

fn ip_target(addr: SocketAddr) -> TargetAddr {
    TargetAddr {
        host: Host::V4(Ipv4Addr::LOCALHOST),
        port: addr.port(),
    }
}

#[tokio::test]
async fn c08_t1_connect_to_tcp_echo_both_ways() {
    let (addr, pin, _, _) = start(true).await;
    let echo = echo_server().await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let (mut send, mut recv) = open(&client, ip_target(echo), b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let writer = async {
        send.write_all(&data).await.unwrap();
        send.shutdown().await.unwrap();
    };
    let mut back = Vec::new();
    let reader = recv.read_to_end(&mut back);
    let (_, read) = tokio::join!(writer, reader);
    read.unwrap();
    assert_eq!(back, data);
}

#[tokio::test]
async fn c08_t2_domain_is_resolved_on_the_server() {
    let (addr, pin, _, _) = start(true).await;
    let echo = echo_server().await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    // The client sends the name unresolved; the server looks it up (hosts file here).
    let target = TargetAddr {
        host: Host::Domain("localhost".into()),
        port: echo.port(),
    };
    let (mut send, mut recv) = open(&client, target, b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    send.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn c08_t3_unreachable_and_refused_targets_reset_with_codes() {
    let (addr, pin, _, _) = start(true).await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let (_send, mut recv) = open(&client, ip_target(closed), b"").await;
    assert_eq!(read_result(&mut recv).await, Err(ErrorCode::TARGET_REFUSED));

    let nowhere = TargetAddr {
        host: Host::Domain("unreachable.invalid".into()),
        port: 80,
    };
    let (_send, mut recv) = open(&client, nowhere, b"").await;
    assert_eq!(
        read_result(&mut recv).await,
        Err(ErrorCode::TARGET_UNREACHABLE)
    );
}

#[tokio::test]
async fn c08_t4_internal_targets_are_not_allowed() {
    let (addr, pin, _, _) = start(false).await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let targets = [
        Host::V4(Ipv4Addr::LOCALHOST),
        Host::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Host::V4(Ipv4Addr::new(169, 254, 169, 254)),
        // A name that resolves to loopback is caught after resolution.
        Host::Domain("localhost".into()),
    ];
    for host in targets {
        let (_send, mut recv) = open(
            &client,
            TargetAddr {
                host: host.clone(),
                port: 80,
            },
            b"",
        )
        .await;
        assert_eq!(
            read_result(&mut recv).await,
            Err(ErrorCode::NOT_ALLOWED),
            "{host:?}"
        );
    }
}

#[tokio::test]
async fn c08_t5_fast_open_data_before_connect_result_arrives() {
    let (addr, pin, _, _) = start(true).await;
    let echo = echo_server().await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    // Header and payload in one write, before the result is read.
    let (mut send, mut recv) = open(&client, ip_target(echo), b"GET / HTTP/1.1\r\n\r\n").await;
    send.shutdown().await.unwrap();
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"GET / HTTP/1.1\r\n\r\n");
}

#[tokio::test]
async fn c08_t6_half_close_passes_through_both_ways() {
    let (addr, pin, _, _) = start(true).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    // Target: reads to EOF (client FIN), then answers and closes.
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        tcp.read_to_end(&mut got).await.unwrap();
        tcp.write_all(format!("got {} bytes", got.len()).as_bytes())
            .await
            .unwrap();
        tcp.shutdown().await.unwrap();
    });
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let (mut send, mut recv) = open(&client, ip_target(target), b"hello").await;
    send.shutdown().await.unwrap();
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"got 5 bytes");

    // The other way: the target closes its side first, the client keeps sending.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = tcp.into_split();
        w.write_all(b"bye").await.unwrap();
        w.shutdown().await.unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        done_tx.send(got).unwrap();
    });
    let (mut send, mut recv) = open(&client, ip_target(target), b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"bye");
    send.write_all(b"still talking").await.unwrap();
    send.shutdown().await.unwrap();
    assert_eq!(done_rx.await.unwrap(), b"still talking");
}

#[tokio::test]
async fn bad_token_gets_not_found_and_reload_applies_revocation() {
    let (addr, pin, state, devices) = start(true).await;
    assert_eq!(
        connect(addr, pin, [0; 32]).await.err(),
        Some(HandshakeError::Rejected)
    );
    assert!(connect(addr, pin, TOKEN).await.is_ok());
    // C08-T7 is manual (SIGHUP); the reload it triggers is checked here.
    write_registry(&devices, true);
    assert_eq!(state.reload_registry(), Ok(1));
    assert_eq!(
        connect(addr, pin, TOKEN).await.err(),
        Some(HandshakeError::Rejected)
    );
    // A broken file keeps the old registry.
    std::fs::write(&devices, "not toml [").unwrap();
    assert!(state.reload_registry().is_err());
    assert_eq!(
        connect(addr, pin, TOKEN).await.err(),
        Some(HandshakeError::Rejected)
    );
}

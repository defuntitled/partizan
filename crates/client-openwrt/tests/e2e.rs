//! The `partizan` binary as a separate process against an in-process server: SOCKS5 in,
//! QUIC through, TCP out.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use proto::auth::{ConnectionUri, DeviceId, Token, TransportMode};
use server::Server;
use server::config::{
    Config, EgressSection, Limits, ResolverSection, ServerSection, TlsMode, TlsSection,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use transport::QuicConfig;

const ID: DeviceId = DeviceId([3; 16]);
const TOKEN: [u8; 32] = [5; 32];

fn temp_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "partizan-e2e-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Starts a server allowing loopback targets; returns a URI file for the client.
async fn start_server(token: [u8; 32]) -> PathBuf {
    let dir = temp_dir();
    let devices = dir.join("devices.toml");
    let hash = Token::from_bytes(TOKEN).hash().to_hex();
    std::fs::write(
        &devices,
        format!("[[device]]\nid = \"{ID}\"\nname = \"e2e\"\ntoken_sha256 = \"{hash}\"\n"),
    )
    .unwrap();
    let config = Config {
        server: ServerSection {
            domain: Some("localhost".into()),
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_path: "/api/v2/sync".into(),
            devices,
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
            allow: vec!["127.0.0.0/8".parse().unwrap(), "::1".parse().unwrap()],
        },
        quic: QuicConfig::default(),
        resolver: ResolverSection {
            timeout: Duration::from_millis(500),
            attempts: 1,
        },
    };
    let server = Server::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap();
    let uri = ConnectionUri {
        device_id: ID,
        token: Token::from_bytes(token),
        host: "127.0.0.1".into(),
        port: addr.port(),
        sni: Some("localhost".into()),
        path: "/api/v2/sync".into(),
        pin: Some(server.pin()),
        transport: TransportMode::Quic,
        insecure: false,
        passthrough: None,
    };
    tokio::spawn(server.run());
    let path = dir.join("uri");
    std::fs::write(&path, uri.to_uri_string().as_bytes()).unwrap();
    path
}

/// The client process; killed on drop.
struct Client {
    child: Child,
    socks: SocketAddr,
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_client(uri: &PathBuf, extra: &[&str]) -> Client {
    // Port 0: the client picks a free port and logs it, so parallel tests never collide.
    let child = Command::new(env!("CARGO_BIN_EXE_partizan"))
        .args(["run", "--uri-file"])
        .arg(uri)
        .args(["--socks", "127.0.0.1:0", "--log-level", "info"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut client = Client {
        child,
        socks: "0.0.0.0:0".parse().unwrap(),
    };
    let stderr = client.child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if let Some(addr) = line.strip_prefix("info: SOCKS5 on ") {
                let _ = tx.send(addr.parse::<SocketAddr>().unwrap());
            }
            // Keep draining so the client never blocks on a full pipe.
        }
    });
    client.socks = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .expect("client did not report its SOCKS address");
    client
}

/// SOCKS5 CONNECT with no auth; returns the stream and the `REP` code.
async fn socks_connect(socks: SocketAddr, atyp_addr: &[u8], port: u16) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(atyp_addr);
    request.extend_from_slice(&port.to_be_bytes());
    s.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    (s, reply[1])
}

fn v4(ip: Ipv4Addr) -> Vec<u8> {
    [&[1u8][..], &ip.octets()].concat()
}

fn domain(name: &str) -> Vec<u8> {
    [&[3u8, name.len() as u8][..], name.as_bytes()].concat()
}

async fn echo_server(addr: &str) -> Option<SocketAddr> {
    let listener = TcpListener::bind(addr).await.ok()?;
    let local = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Some(local)
}

async fn roundtrip(mut s: TcpStream, data: &[u8]) -> Vec<u8> {
    s.write_all(data).await.unwrap();
    let mut back = vec![0u8; data.len()];
    s.read_exact(&mut back).await.unwrap();
    back
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_t1_curl_through_socks5_hostname() {
    if Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("curl not installed; skipping");
        return;
    }
    let uri = start_server(TOKEN).await;
    let client = start_client(&uri, &[]).await;
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = http.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = http.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = tcp.read(&mut buf).await;
                let body = "hello through partizan";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tcp.write_all(response.as_bytes()).await;
            });
        }
    });
    let output = tokio::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "10",
            "--socks5-hostname",
            &client.socks.to_string(),
        ])
        .arg(format!("http://localhost:{port}/"))
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "curl failed: {output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "hello through partizan"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_t2_connect_with_ipv4_ipv6_and_domain() {
    let uri = start_server(TOKEN).await;
    let client = start_client(&uri, &[]).await;
    let echo4 = echo_server("127.0.0.1:0").await.unwrap();

    let (s, rep) = socks_connect(client.socks, &v4(Ipv4Addr::LOCALHOST), echo4.port()).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(s, b"over ipv4").await, b"over ipv4");

    let (s, rep) = socks_connect(client.socks, &domain("localhost"), echo4.port()).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(s, b"over a name").await, b"over a name");

    match echo_server("[::1]:0").await {
        Some(echo6) => {
            let addr = [&[4u8][..], &Ipv6Addr::LOCALHOST.octets()].concat();
            let (s, rep) = socks_connect(client.socks, &addr, echo6.port()).await;
            assert_eq!(rep, 0);
            assert_eq!(roundtrip(s, b"over ipv6").await, b"over ipv6");
        }
        None => eprintln!("no IPv6 loopback here; IPv6 part skipped"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_t3_bind_is_refused_with_rep_07() {
    let uri = start_server(TOKEN).await;
    let client = start_client(&uri, &[]).await;
    let mut s = TcpStream::connect(client.socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    s.write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x07);
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_t4_target_errors_map_to_rep_codes() {
    let uri = start_server(TOKEN).await;
    let honest = start_client(&uri, &["--honest-connect"]).await;
    let closed = StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (_, rep) = socks_connect(honest.socks, &v4(Ipv4Addr::LOCALHOST), closed.port()).await;
    assert_eq!(rep, 0x05, "refused");
    let (_, rep) = socks_connect(honest.socks, &v4(Ipv4Addr::new(10, 0, 0, 1)), 80).await;
    assert_eq!(rep, 0x02, "not allowed");
    let (_, rep) = socks_connect(honest.socks, &domain("unreachable.invalid"), 80).await;
    assert_eq!(rep, 0x04, "unreachable");

    // Fast mode answers success at once and reports the failure by closing.
    let fast = start_client(&uri, &[]).await;
    let (mut s, rep) = socks_connect(fast.socks, &v4(Ipv4Addr::LOCALHOST), closed.port()).await;
    assert_eq!(rep, 0);
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "connection stays open: {read:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn c09_t6_check_passes_on_a_valid_uri_and_fails_on_a_bad_one() {
    let good = start_server(TOKEN).await;
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_partizan"))
        .args(["check", "--uri-file"])
        .arg(&good)
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("ok: QUIC"));

    let bad = start_server([0; 32]).await;
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_partizan"))
        .args(["check", "--uri-file"])
        .arg(&bad)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("authentication rejected"), "{stdout}");
    // The token never appears in what the user sees.
    let token = Token::from_bytes([0; 32]).to_base64url();
    assert!(!stdout.contains(token.as_str()));
}

/// Opens a UDP association; returns the control connection (keep it open) and the relay.
async fn socks_udp_associate(socks: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "UDP ASSOCIATE refused");
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    (s, relay)
}

/// SOCKS5 UDP request header for an IPv4 destination.
fn udp_header(frag: u8, dst: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = dst else {
        panic!("IPv4 only")
    };
    [
        &[0u8, 0, frag, 1][..],
        &v4.ip().octets(),
        &v4.port().to_be_bytes(),
    ]
    .concat()
}

async fn udp_reply(socket: &tokio::net::UdpSocket) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(buf[..n].to_vec())
}

/// Answers DNS-shaped queries: same ID, QR bit set; records every source it saw.
async fn fake_dns() -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>,
) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let query = buf[..n].to_vec();
            let _ = tx.send((from, query.clone()));
            if n >= 12 {
                let mut answer = query;
                answer[2] |= 0x80; // QR: response.
                let _ = socket.send_to(&answer, from).await;
            }
        }
    });
    (addr, rx)
}

/// A DNS query for example.com A with transaction id `id`.
fn dns_query(id: u16) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    q
}

#[tokio::test(flavor = "multi_thread")]
async fn c11_t1_dns_query_through_udp_associate() {
    let uri = start_server(TOKEN).await;
    let client = start_client(&uri, &[]).await;
    let (dns, _) = fake_dns().await;
    let (_control, relay) = socks_udp_associate(client.socks).await;
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.send_to(&[udp_header(0, dns), dns_query(0xbeef)].concat(), relay)
        .await
        .unwrap();
    let reply = udp_reply(&app).await.expect("DNS answer");
    let header = udp_header(0, dns);
    assert_eq!(
        &reply[..header.len()],
        &header[..],
        "reply names the DNS server as source"
    );
    let answer = &reply[header.len()..];
    assert_eq!(&answer[..2], &0xbeefu16.to_be_bytes());
    assert_ne!(answer[2] & 0x80, 0, "QR set");
}

#[tokio::test(flavor = "multi_thread")]
async fn c11_t2_two_sources_get_separate_udp_sessions() {
    let uri = start_server(TOKEN).await;
    let client = start_client(&uri, &[]).await;
    let (dns, mut seen) = fake_dns().await;
    let (_control, relay) = socks_udp_associate(client.socks).await;
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(&[udp_header(0, dns), dns_query(1)].concat(), relay)
        .await
        .unwrap();
    b.send_to(&[udp_header(0, dns), dns_query(2)].concat(), relay)
        .await
        .unwrap();
    // Each source gets only its own answer.
    let ra = udp_reply(&a).await.unwrap();
    let rb = udp_reply(&b).await.unwrap();
    let hl = udp_header(0, dns).len();
    assert_eq!(&ra[hl..hl + 2], &1u16.to_be_bytes());
    assert_eq!(&rb[hl..hl + 2], &2u16.to_be_bytes());
    // Separate UDP sessions on the server: two NAT sockets, two source ports.
    let (from1, _) = seen.recv().await.unwrap();
    let (from2, _) = seen.recv().await.unwrap();
    assert_ne!(from1, from2);
}

#[tokio::test(flavor = "multi_thread")]
async fn c11_t3_closing_the_control_connection_ends_the_association() {
    let uri = start_server(TOKEN).await;
    let client = start_client(&uri, &[]).await;
    let (dns, _) = fake_dns().await;
    let (control, relay) = socks_udp_associate(client.socks).await;
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.connect(relay).await.unwrap();
    app.send(&[udp_header(0, dns), dns_query(3)].concat())
        .await
        .unwrap();
    assert!(udp_reply(&app).await.is_some());
    drop(control);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The relay socket is gone: the kernel answers with port unreachable.
    app.send(&[udp_header(0, dns), dns_query(4)].concat())
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let after = tokio::time::timeout(Duration::from_secs(2), app.recv(&mut buf)).await;
    assert!(
        matches!(after, Ok(Err(_)) | Err(_)),
        "relay still answering: {after:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn c11_t4_fragments_are_dropped() {
    let uri = start_server(TOKEN).await;
    let client = start_client(&uri, &[]).await;
    let (dns, mut seen) = fake_dns().await;
    let (_control, relay) = socks_udp_associate(client.socks).await;
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.send_to(&[udp_header(1, dns), dns_query(5)].concat(), relay)
        .await
        .unwrap();
    app.send_to(&[udp_header(0, dns), dns_query(6)].concat(), relay)
        .await
        .unwrap();
    let reply = udp_reply(&app).await.unwrap();
    let hl = udp_header(0, dns).len();
    assert_eq!(
        &reply[hl..hl + 2],
        &6u16.to_be_bytes(),
        "only the unfragmented query went through"
    );
    let (_, query) = seen.recv().await.unwrap();
    assert_eq!(&query[..2], &6u16.to_be_bytes());
    assert!(seen.try_recv().is_err());
}

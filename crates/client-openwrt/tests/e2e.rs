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
    let socks = StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_partizan"))
        .args(["run", "--uri-file"])
        .arg(uri)
        .args(["--socks", &socks.to_string(), "--log-level", "warn"])
        .args(extra)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    // Owned by `Client` from here, so a failed wait below still reaps it.
    let client = Client { child, socks };
    for _ in 0..100 {
        if TcpStream::connect(socks).await.is_ok() {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("client did not open SOCKS on {socks}");
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

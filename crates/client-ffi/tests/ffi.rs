//! The FFI surface against a real server, with a socketpair standing in for the TUN fd.
//!
//! The calls share one global tunnel, so the tests take turns.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once};
use std::time::{Duration, Instant};

use client_ffi::{
    SplitConfig, SplitMode, StatusListener, VpnConfig, VpnError, VpnState, VpnStatus,
};
use proto::auth::{ConnectionUri, DeviceId, Token, TransportMode};
use server::Server;
use server::config::{
    Config, EgressSection, Limits, ResolverSection, ServerSection, TlsMode, TlsSection,
};
use transport::QuicConfig;

const ID: DeviceId = DeviceId([4; 16]);
const TOKEN: [u8; 32] = [6; 32];

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Every log line of the process, to look for the token.
static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        let line = format!("{} {}: {}", record.level(), record.target(), record.args());
        LOG.lock().unwrap_or_else(|e| e.into_inner()).push(line);
    }
    fn flush(&self) {}
}

fn capture_logs() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        log::set_logger(&Capture).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    });
}

/// A server on loopback with this device registered; runs until dropped.
struct TestServer {
    runtime: tokio::runtime::Runtime,
    addr: SocketAddr,
    state: Arc<server::State>,
    pin: [u8; 32],
}

fn server() -> TestServer {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "partizan-ffi-{}-{}",
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
        format!("[[device]]\nid = \"{ID}\"\nname = \"ffi\"\ntoken_sha256 = \"{hash}\"\n"),
    )
    .unwrap();
    let config = Config {
        server: ServerSection {
            domain: None,
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_path: "/sync".into(),
            devices: dir.join("devices.toml"),
            admin_sock: None,
        },
        tls: TlsSection {
            mode: TlsMode::Files,
            cert: Some(dir.join("cert.pem")),
            key: Some(dir.join("key.pem")),
        },
        limits: Limits::default(),
        egress: EgressSection {
            deny_private: true,
            allow: vec!["127.0.0.0/8".parse().unwrap()],
        },
        quic: QuicConfig::default(),
        resolver: ResolverSection::default(),
        bench: Default::default(),
        masquerade: Default::default(),
        metrics: Default::default(),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (addr, state) = runtime.block_on(async {
        let server = Server::bind(config).await.unwrap();
        let (addr, state) = (server.local_addr().unwrap(), server.state());
        tokio::spawn(server.run());
        (addr, state)
    });
    TestServer {
        runtime,
        addr,
        state,
        pin: transport::tls::spki_pin(cert.der()).unwrap(),
    }
}

impl TestServer {
    fn uri(&self, transport: TransportMode) -> String {
        ConnectionUri {
            device_id: ID,
            token: Token::from_bytes(TOKEN),
            host: "127.0.0.1".into(),
            port: self.addr.port(),
            sni: Some("localhost".into()),
            path: "/sync".into(),
            pin: Some(self.pin),
            transport,
            insecure: false,
            passthrough: None,
        }
        .to_uri_string()
        .to_string()
    }

    /// A UDP echo on loopback, reachable through the tunnel.
    fn udp_echo(&self) -> SocketAddr {
        let socket = self
            .runtime
            .block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        self.runtime.spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], from).await;
            }
        });
        addr
    }
}

/// The token as it appears in the link.
fn token_text(uri: &str) -> String {
    let userinfo = uri.split('@').next().unwrap();
    userinfo.rsplit(':').next().unwrap().to_owned()
}

#[derive(Default)]
struct Recorder(Mutex<Vec<VpnStatus>>);

impl StatusListener for Recorder {
    fn on_status(&self, status: VpnStatus) {
        self.0.lock().unwrap().push(status);
    }
}

impl Recorder {
    fn states(&self) -> Vec<VpnState> {
        self.0.lock().unwrap().iter().map(|s| s.state).collect()
    }
}

fn config(uri: String) -> VpnConfig {
    VpnConfig {
        uri,
        split: SplitConfig {
            mode: SplitMode::Exclude,
            routes: Vec::new(),
        },
        mtu: 1400,
    }
}

/// A socketpair: one end is the "TUN fd" handed over, the other plays the apps.
fn tun_pair() -> (i32, UnixDatagram) {
    let (tun, apps) = UnixDatagram::pair().unwrap();
    apps.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    (tun.into_raw_fd(), apps)
}

fn eventually(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// IPv4 + UDP packet; the UDP checksum is left at zero (allowed over IPv4).
fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let len = 20 + 8 + payload.len();
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.ip().octets());
    p[16..20].copy_from_slice(&dst.ip().octets());
    let sum = (0..20)
        .step_by(2)
        .map(|i| u32::from(u16::from_be_bytes([p[i], p[i + 1]])))
        .sum::<u32>();
    let sum = (sum & 0xffff) + (sum >> 16);
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p[20..22].copy_from_slice(&src.port().to_be_bytes());
    p[22..24].copy_from_slice(&dst.port().to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

#[test]
fn a03_t1_check_uri_accepts_a_working_link_and_explains_a_broken_one() {
    let _turn = serial();
    let server = server();
    let result = client_ffi::check_uri(server.uri(TransportMode::Auto)).unwrap();
    assert_eq!(
        (result.host.as_str(), result.port),
        ("127.0.0.1", server.addr.port())
    );
    assert!(
        result.quic_ms.is_some() && result.tls_ms.is_some(),
        "{result:?}"
    );

    for broken in [
        "",
        "https://example.com",
        "partizan://nonsense",
        "partizan://00000000000000000000000000000000:short@host?path=/x",
    ] {
        match client_ffi::check_uri(broken.into()) {
            Err(VpnError::InvalidUri { reason }) => assert!(!reason.is_empty()),
            other => panic!("{broken:?}: {other:?}"),
        }
    }
    // Well-formed but nobody listens.
    let closed = server
        .uri(TransportMode::Auto)
        .replace(&format!(":{}?", server.addr.port()), ":1?");
    assert!(matches!(
        client_ffi::check_uri(closed),
        Err(VpnError::Unreachable { .. })
    ));
}

#[test]
fn a03_t2_t3_start_connects_reports_transitions_and_carries_traffic() {
    let _turn = serial();
    let server = server();
    let echo = server.udp_echo();
    let (fd, apps) = tun_pair();
    let listener = Arc::new(Recorder::default());
    client_ffi::start(
        fd,
        config(server.uri(TransportMode::Quic)),
        listener.clone(),
    )
    .unwrap();
    assert!(
        eventually(Duration::from_secs(10), || client_ffi::status().state
            == VpnState::Connected),
        "{:?}",
        client_ffi::status()
    );
    let status = client_ffi::status();
    assert_eq!(status.transport.as_deref(), Some("quic"));
    assert!(status.rtt_ms.is_some());

    // A datagram written to the "TUN fd" reaches the echo through the server and comes back.
    let SocketAddr::V4(echo) = echo else {
        unreachable!()
    };
    let app = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000);
    apps.send(&udp_packet(app, echo, b"through")).unwrap();
    let mut buf = [0u8; 2048];
    let n = apps.recv(&mut buf).unwrap();
    assert_eq!(&buf[28..n], b"through");
    assert_eq!(
        &buf[12..16],
        &echo.ip().octets(),
        "reply comes from the echo"
    );
    assert!(eventually(Duration::from_secs(2), || {
        let s = client_ffi::status();
        s.tx_bytes >= 7 && s.rx_bytes >= 7
    }));

    // A03-T3: the listener saw the way up.
    let states = listener.states();
    assert_eq!(states.first(), Some(&VpnState::Connecting), "{states:?}");
    assert!(states.contains(&VpnState::Connected), "{states:?}");

    assert_eq!(
        client_ffi::start(
            -1,
            config(server.uri(TransportMode::Quic)),
            listener.clone()
        ),
        Err(VpnError::AlreadyRunning)
    );
    client_ffi::stop();
}

#[test]
fn a03_t4_stop_closes_the_session_and_releases_the_fd() {
    let _turn = serial();
    let server = server();
    let (fd, apps) = tun_pair();
    let listener = Arc::new(Recorder::default());
    client_ffi::start(
        fd,
        config(server.uri(TransportMode::Quic)),
        listener.clone(),
    )
    .unwrap();
    assert!(eventually(Duration::from_secs(10), || {
        client_ffi::status().state == VpnState::Connected
    }));
    assert_eq!(server.state.sessions.len(), 1);

    client_ffi::stop();
    assert_eq!(client_ffi::status().state, VpnState::Idle);
    assert_eq!(listener.states().last(), Some(&VpnState::Idle));
    assert!(
        eventually(Duration::from_secs(3), || server.state.sessions.is_empty()),
        "the server saw the session close"
    );
    // Our end of the pair is closed: the apps' side can no longer send to it.
    assert!(apps.send(b"x").is_err());
    // Stopping twice is harmless, and the tunnel can come up again.
    client_ffi::stop();
    let (fd, _apps) = tun_pair();
    client_ffi::start(fd, config(server.uri(TransportMode::Tls)), listener.clone()).unwrap();
    assert!(eventually(Duration::from_secs(10), || {
        client_ffi::status().transport.as_deref() == Some("tls")
    }));
    client_ffi::stop();
}

#[test]
fn a03_t5_the_token_shows_up_in_no_string_and_no_log() {
    let _turn = serial();
    capture_logs();
    let server = server();
    let uri = server.uri(TransportMode::Auto);
    let token = token_text(&uri);
    assert!(token.len() >= 32 && uri.contains(&token));

    let mut seen: Vec<String> = Vec::new();
    // Errors from links that carry a token.
    let unreachable = uri.replace(&format!(":{}?", server.addr.port()), ":1?");
    seen.push(format!("{:?}", client_ffi::check_uri(unreachable.clone())));
    let broken = uri.replace("path=", "path");
    seen.push(format!("{:?}", client_ffi::check_uri(broken.clone())));
    let mut bad_config = config(uri.clone());
    bad_config.mtu = 100;
    seen.push(format!(
        "{:?}",
        client_ffi::start(-1, bad_config, Arc::new(Recorder::default()))
    ));
    seen.push(format!(
        "{:?}",
        client_ffi::start(-1, config(uri.clone()), Arc::new(Recorder::default()))
    ));
    // A full run, including one against a server that is not there.
    let listener = Arc::new(Recorder::default());
    let (fd, _apps) = tun_pair();
    client_ffi::start(fd, config(uri.clone()), listener.clone()).unwrap();
    assert!(eventually(Duration::from_secs(10), || {
        client_ffi::status().state == VpnState::Connected
    }));
    client_ffi::stop();
    let (fd, _apps) = tun_pair();
    client_ffi::start(fd, config(unreachable), listener.clone()).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    client_ffi::stop();
    seen.extend(listener.0.lock().unwrap().iter().map(|s| format!("{s:?}")));

    for text in &seen {
        assert!(!text.contains(&token), "token in {text}");
    }
    let log = LOG.lock().unwrap();
    assert!(!log.is_empty());
    for line in log.iter() {
        assert!(!line.contains(&token), "token in log: {line}");
    }
}

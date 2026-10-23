//! Server fixture and helpers shared by the engine integration tests.

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use client_core::{Engine, EngineConfig};
use proto::auth::{ClientInfo, ConnectionUri, DeviceId, Token, TransportMode};
use proto::{Host, TargetAddr};
use server::Server;
use server::config::{
    Config, EgressSection, Limits, ResolverSection, ServerSection, TlsMode, TlsSection,
};
use tokio::net::{TcpListener, UdpSocket};
use transport::QuicConfig;

pub const ID: DeviceId = DeviceId([4; 16]);
pub const TOKEN: [u8; 32] = [6; 32];

pub struct Fixture {
    pub dir: PathBuf,
    pub pin: [u8; 32],
}

/// Certificate files and a registry, shared by every server start so the pin stays.
pub fn fixture() -> Fixture {
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

pub async fn start_server(
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
        bench: Default::default(),
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

pub async fn stop_server(endpoint: quinn::Endpoint) {
    endpoint.close(0u32.into(), b"restart");
    endpoint.wait_idle().await;
}

pub fn engine(f: &Fixture, addr: SocketAddr) -> Engine {
    engine_with(f, addr, TransportMode::Quic, client_core::FALLBACK_MEMORY)
}

/// Engine for `addr` with the given transport mode and fallback memory.
pub fn engine_with(
    f: &Fixture,
    addr: SocketAddr,
    transport: TransportMode,
    fallback_memory: Duration,
) -> Engine {
    let uri = ConnectionUri {
        device_id: ID,
        token: Token::from_bytes(TOKEN),
        host: "127.0.0.1".into(),
        port: addr.port(),
        sni: Some("localhost".into()),
        path: "/sync".into(),
        pin: Some(f.pin),
        transport,
        insecure: false,
        passthrough: None,
    };
    Engine::new(EngineConfig {
        uri,
        quic: QuicConfig::default(),
        info: ClientInfo::new("test", "0.1.0"),
        fallback_memory,
    })
}

pub fn target(addr: SocketAddr) -> TargetAddr {
    TargetAddr {
        host: Host::V4(Ipv4Addr::LOCALHOST),
        port: addr.port(),
    }
}

pub async fn tcp_echo() -> SocketAddr {
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

pub async fn udp_echo() -> SocketAddr {
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
pub async fn eventually(timeout: Duration, mut f: impl AsyncFnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

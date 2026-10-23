//! Test server and client shared by the server integration tests.

#![allow(dead_code)]

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

pub const ID: DeviceId = DeviceId([7; 16]);
pub const TOKEN: [u8; 32] = [9; 32];

pub fn temp_path(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "partizan-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

pub fn write_registry(path: &PathBuf, revoked: bool) {
    let hash = Token::from_bytes(TOKEN).hash().to_hex();
    let text = format!(
        "[[device]]\nid = \"{ID}\"\nname = \"router\"\ntoken_sha256 = \"{hash}\"\nrevoked = {revoked}\n"
    );
    std::fs::write(path, text).unwrap();
}

/// Server on loopback; `allow_loopback` lets it dial local test targets.
pub async fn start(
    allow_loopback: bool,
) -> (SocketAddr, [u8; 32], std::sync::Arc<server::State>, PathBuf) {
    start_with(allow_loopback, Limits::default()).await
}

/// Like [`start`] with explicit limits.
pub async fn start_with(
    allow_loopback: bool,
    limits: Limits,
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
        limits,
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
        bench: Default::default(),
        masquerade: Default::default(),
        metrics: Default::default(),
    };
    let server = Server::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap();
    let pin = server.pin();
    let state = server.state();
    tokio::spawn(server.run());
    (addr, pin, state, devices)
}

pub fn uri(token: [u8; 32]) -> ConnectionUri {
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
pub struct Client {
    pub transport: QuicTransport,
    pub control_send: quinn::SendStream,
    pub control_recv: quinn::RecvStream,
    pub leftover: Vec<u8>,
    _h3_control: quinn::SendStream,
    _endpoint: quinn::Endpoint,
}

pub async fn connect(
    addr: SocketAddr,
    pin: [u8; 32],
    token: [u8; 32],
) -> Result<Client, HandshakeError> {
    connect_uri(addr, pin, &uri(token)).await
}

/// Connects with the credentials of `uri` (its address is ignored: `addr` is used).
pub async fn connect_uri(
    addr: SocketAddr,
    pin: [u8; 32],
    uri: &ConnectionUri,
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
        ClientHandshake::start(AuthTransport::Quic, uri, &info, Instant::now()).unwrap();
    send.write_all(&request).await.unwrap();
    let mut buf = [0u8; 4096];
    loop {
        let n = recv.read(&mut buf).await.unwrap().unwrap_or(0);
        if n == 0 {
            return Err(HandshakeError::Rejected);
        }
        if let Some(established) = handshake.handle_input(&buf[..n])? {
            return Ok(Client {
                transport,
                control_send: send,
                control_recv: recv,
                leftover: established.leftover,
                _h3_control: h3_control,
                _endpoint: endpoint,
            });
        }
    }
}

/// Opens a stream with `Connect` (plus `early` bytes in the same write).
pub async fn open(client: &Client, target: TargetAddr, early: &[u8]) -> (SendHalf, RecvHalf) {
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
pub async fn read_result(recv: &mut RecvHalf) -> Result<ConnectStatus, ErrorCode> {
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

pub fn reset_code(e: &std::io::Error) -> Option<ErrorCode> {
    match e.get_ref()?.downcast_ref::<quinn::ReadError>()? {
        quinn::ReadError::Reset(code) => Some(ErrorCode(code.into_inner())),
        _ => None,
    }
}

pub async fn echo_server() -> SocketAddr {
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

pub fn ip_target(addr: SocketAddr) -> TargetAddr {
    TargetAddr {
        host: Host::V4(Ipv4Addr::LOCALHOST),
        port: addr.port(),
    }
}

impl Client {
    /// Next control frame from the server, unwrapped from HTTP/3 `DATA` frames.
    pub async fn next_control(
        &mut self,
        data: &mut proto::auth::DataFrameReader,
        frames: &mut proto::control::ControlReader,
        timeout: Duration,
    ) -> Option<proto::ControlFrame> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut pending: Vec<proto::ControlFrame> = frames
            .push(&data.push(&std::mem::take(&mut self.leftover)).ok()?)
            .ok()?;
        let mut buf = [0u8; 2048];
        loop {
            if !pending.is_empty() {
                return Some(pending.remove(0));
            }
            let n = tokio::time::timeout_at(deadline, self.control_recv.read(&mut buf))
                .await
                .ok()?
                .ok()??;
            pending = frames.push(&data.push(&buf[..n]).ok()?).ok()?;
        }
    }

    /// Sends a control frame to the server.
    pub async fn send_control(&mut self, frame: proto::ControlFrame) {
        let mut body = Vec::new();
        frame.encode(&mut body).unwrap();
        self.control_send
            .write_all(&proto::auth::encode_data_frame(&body))
            .await
            .unwrap();
    }
}

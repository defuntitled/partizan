//! The session with the server: QUIC connection, auth exchange, shared by all streams.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proto::auth::{
    ClientHandshake, ClientInfo, ConnectionUri, DataFrameReader, HANDSHAKE_TIMEOUT, HandshakeError,
    SessionInfo, Transport as AuthTransport, client_control_stream, encode_data_frame,
};
use proto::control::ControlReader;
use proto::{ControlFrame, UdpDatagram};
use quinn::Endpoint;
use tokio::sync::{Mutex, mpsc};
use tokio::task::AbortHandle;
use transport::quic::{self, QuicTransport};
use transport::tls::{self, ALPN_H3, ServerVerification};
use transport::{QuicConfig, Transport, TransportStats};

use crate::udp::UdpRegistry;

/// What the engine needs to reach the server.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Connection URI.
    pub uri: ConnectionUri,
    /// QUIC tuning.
    pub quic: QuicConfig,
    /// Client info sent in `x-client`.
    pub info: ClientInfo,
}

/// Session setup failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// Server address did not resolve.
    #[error("cannot resolve server: {0}")]
    Resolve(String),
    /// Transport or TLS failure.
    #[error("connection failed: {0}")]
    Connect(String),
    /// Auth exchange failed.
    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),
}

/// Session snapshot for `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// `true` while a session is up.
    pub connected: bool,
    /// Transport name, `quic` or `tls`.
    pub transport: Option<&'static str>,
    /// What the server granted.
    pub session: Option<SessionInfo>,
    /// Transport counters.
    pub stats: TransportStats,
}

/// An authenticated connection.
pub(crate) struct Session {
    pub(crate) transport: QuicTransport,
    pub(crate) info: SessionInfo,
    /// Frames to send on the control channel.
    pub(crate) control: mpsc::Sender<ControlFrame>,
    // Kept open for the session's lifetime: the endpoint socket and the HTTP/3 control stream.
    _endpoint: Endpoint,
    _h3_control: quinn::SendStream,
    tasks: Vec<AbortHandle>,
}

impl Session {
    pub(crate) fn is_alive(&self) -> bool {
        self.transport.connection().close_reason().is_none()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The client engine: one session, many proxied connections.
#[derive(Clone)]
pub struct Engine {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    config: EngineConfig,
    pub(crate) session: Mutex<Option<Arc<Session>>>,
    pub(crate) udp: Arc<UdpRegistry>,
}

impl Engine {
    /// Engine for `config`; no connection is made until [`Engine::connect`] or first use.
    pub fn new(config: EngineConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                session: Mutex::new(None),
                udp: Arc::new(UdpRegistry::default()),
            }),
        }
    }

    /// Brings the session up now, so the first connection does not wait for a handshake.
    pub async fn connect(&self) -> Result<SessionInfo, EngineError> {
        Ok(self.session().await?.info)
    }

    /// The live session, establishing one if needed. Concurrent callers share one attempt.
    pub(crate) async fn session(&self) -> Result<Arc<Session>, EngineError> {
        let mut slot = self.inner.session.lock().await;
        if let Some(session) = slot.as_ref().filter(|s| s.is_alive()) {
            return Ok(session.clone());
        }
        let session = Arc::new(establish(&self.inner.config, self.inner.udp.clone()).await?);
        // UDP sessions of the old connection are gone on the server; the next datagram of every
        // flow carries its address again.
        self.inner.udp.reset_all();
        *slot = Some(session.clone());
        Ok(session)
    }

    /// Current state.
    pub async fn status(&self) -> Status {
        let slot = self.inner.session.lock().await;
        match slot.as_ref().filter(|s| s.is_alive()) {
            Some(s) => Status {
                connected: true,
                transport: Some("quic"),
                session: Some(s.info),
                stats: s.transport.stats(),
            },
            None => Status {
                connected: false,
                transport: None,
                session: None,
                stats: TransportStats::default(),
            },
        }
    }
}

/// Resolves the server, connects over QUIC and runs the auth exchange.
async fn establish(config: &EngineConfig, udp: Arc<UdpRegistry>) -> Result<Session, EngineError> {
    let uri = &config.uri;
    let addr = resolve(&uri.host, uri.port).await?;
    let tls = tls::client_config(ServerVerification::from_uri(uri), &[ALPN_H3])
        .map_err(|e| EngineError::Connect(e.to_string()))?;
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("literal address");
    let endpoint = quic::client_endpoint(bind, tls, &config.quic)
        .map_err(|e| EngineError::Connect(e.to_string()))?;
    let started = Instant::now();
    let transport = quic::connect(&endpoint, addr, uri.server_name())
        .await
        .map_err(|e| EngineError::Connect(e.to_string()))?;
    let conn = transport.connection().clone();
    let auth = async {
        let mut h3_control = conn.open_uni().await.map_err(io)?;
        h3_control
            .write_all(&client_control_stream())
            .await
            .map_err(io)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(io)?;
        let (mut handshake, request) =
            ClientHandshake::start(AuthTransport::Quic, uri, &config.info, Instant::now())?;
        send.write_all(&request).await.map_err(io)?;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = recv.read(&mut buf).await.map_err(io)?.unwrap_or(0);
            if n == 0 {
                return Err(EngineError::Handshake(HandshakeError::Rejected));
            }
            if let Some(established) = handshake.handle_input(&buf[..n])? {
                return Ok((established, h3_control, send, recv));
            }
        }
    };
    let (established, h3_control, send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, auth)
        .await
        .map_err(|_| EngineError::Handshake(HandshakeError::Timeout))??;
    let info = established.session;
    let (control, control_rx) = mpsc::channel(64);
    let tasks = vec![
        tokio::spawn(write_control(send, control_rx)).abort_handle(),
        tokio::spawn(read_control(recv, established.leftover, udp.clone())).abort_handle(),
        tokio::spawn(read_datagrams(transport.clone(), udp)).abort_handle(),
    ];
    log::info!(
        "session up via QUIC to {addr} in {} ms (sid {:x}, caps {:x})",
        started.elapsed().as_millis(),
        info.sid,
        info.caps.0
    );
    Ok(Session {
        transport,
        info,
        control,
        _endpoint: endpoint,
        _h3_control: h3_control,
        tasks,
    })
}

/// Sends control frames, each in an HTTP/3 `DATA` frame on the auth stream.
async fn write_control(mut send: quinn::SendStream, mut frames: mpsc::Receiver<ControlFrame>) {
    while let Some(frame) = frames.recv().await {
        let mut body = Vec::new();
        if frame.encode(&mut body).is_ok()
            && send.write_all(&encode_data_frame(&body)).await.is_err()
        {
            return;
        }
    }
}

/// Handles the server's control frames.
async fn read_control(mut recv: quinn::RecvStream, leftover: Vec<u8>, udp: Arc<UdpRegistry>) {
    let (mut data, mut frames) = (DataFrameReader::default(), ControlReader::default());
    let mut bytes = leftover;
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok(payload) = data.push(&bytes) else {
            return;
        };
        let Ok(parsed) = frames.push(&payload) else {
            return;
        };
        for frame in parsed {
            if let ControlFrame::UdpClose { session_id, reason } = frame {
                log::debug!("server closed UDP session {session_id} (reason {reason})");
                udp.server_closed(session_id);
            }
        }
        match recv.read(&mut buf).await {
            Ok(Some(n)) => bytes = buf[..n].to_vec(),
            _ => return,
        }
    }
}

/// Hands incoming datagrams to their UDP flows.
async fn read_datagrams(transport: QuicTransport, udp: Arc<UdpRegistry>) {
    while let Ok(raw) = transport.recv_datagram().await {
        match UdpDatagram::decode(raw) {
            Ok(datagram) => udp.deliver(datagram),
            Err(_) => log::debug!("malformed datagram from the server dropped"),
        }
    }
}

fn io(e: impl std::fmt::Display) -> EngineError {
    EngineError::Connect(e.to_string())
}

/// Resolves the server host with the system resolver; literal IPs pass through.
async fn resolve(host: &str, port: u16) -> Result<SocketAddr, EngineError> {
    let lookup = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    );
    let mut addrs = lookup
        .await
        .map_err(|_| EngineError::Resolve(format!("{host}: timed out")))?
        .map_err(|e| EngineError::Resolve(format!("{host}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| EngineError::Resolve(format!("{host}: no addresses")))
}

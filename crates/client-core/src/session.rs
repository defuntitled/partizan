//! The session with the server: QUIC connection, auth exchange, shared by all streams.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proto::auth::{
    ClientHandshake, ClientInfo, ConnectionUri, HANDSHAKE_TIMEOUT, HandshakeError, SessionInfo,
    Transport as AuthTransport, client_control_stream,
};
use quinn::Endpoint;
use tokio::sync::Mutex;
use transport::quic::{self, QuicTransport};
use transport::tls::{self, ALPN_H3, ServerVerification};
use transport::{QuicConfig, Transport, TransportStats};

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
    // Kept open for the session's lifetime: the endpoint socket, the HTTP/3 control stream and
    // the auth stream that carries the control channel.
    _endpoint: Endpoint,
    _h3_control: quinn::SendStream,
    _control: (quinn::SendStream, quinn::RecvStream),
}

impl Session {
    fn is_alive(&self) -> bool {
        self.transport.connection().close_reason().is_none()
    }
}

/// The client engine: one session, many proxied connections.
#[derive(Clone)]
pub struct Engine {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    config: EngineConfig,
    session: Mutex<Option<Arc<Session>>>,
}

impl Engine {
    /// Engine for `config`; no connection is made until [`Engine::connect`] or first use.
    pub fn new(config: EngineConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                session: Mutex::new(None),
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
        let session = Arc::new(establish(&self.inner.config).await?);
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
async fn establish(config: &EngineConfig) -> Result<Session, EngineError> {
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
                return Ok((established.session, h3_control, send, recv));
            }
        }
    };
    let (info, h3_control, send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, auth)
        .await
        .map_err(|_| EngineError::Handshake(HandshakeError::Timeout))??;
    log::info!(
        "session up via QUIC to {addr} in {} ms (sid {:x}, caps {:x})",
        started.elapsed().as_millis(),
        info.sid,
        info.caps.0
    );
    Ok(Session {
        transport,
        info,
        _endpoint: endpoint,
        _h3_control: h3_control,
        _control: (send, recv),
    })
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

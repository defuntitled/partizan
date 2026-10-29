//! The session with the server: QUIC connection, auth exchange, shared by all streams.
//!
//! With [`Engine::start`] a supervisor keeps the session up: it reconnects with exponential
//! backoff and jitter, obeys `GoAway`, and stops for good when the device is revoked or the
//! engine is shut down.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use proto::auth::{
    ClientHandshake, ClientInfo, ConnectionUri, HANDSHAKE_TIMEOUT, HandshakeError, SessionInfo,
    Transport as AuthTransport, TransportMode, client_control_stream_seeded,
};
use proto::control::ControlReader;
use proto::mux::Role;
use proto::{ControlFrame, ErrorCode, UdpDatagram};
use quinn::Endpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Notify, mpsc, watch};
use tokio::task::AbortHandle;
use transport::quic::{self, QuicControl};
use transport::tcp::MuxTransport;
use transport::tls::{ALPN_HTTP11, ServerVerification};
use transport::{ControlChannel, QuicConfig, Transport, TransportError, TransportStats};

use crate::udp::UdpRegistry;

/// How long a new connection waits for a session before failing.
pub const SESSION_WAIT: Duration = Duration::from_secs(5);
/// QUIC handshake deadline; past it the server counts as unreachable over QUIC.
pub const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// TCP connect plus TLS handshake deadline.
const TLS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Reconnect backoff bounds.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Longest `retry_after_ms` honoured from a `GoAway`.
const RETRY_AFTER_MAX: Duration = Duration::from_secs(600);
/// On shutdown, how long the QUIC endpoint gets to send its close.
const CLOSE_GRACE: Duration = Duration::from_millis(500);

/// What the engine needs to reach the server.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Connection URI.
    pub uri: ConnectionUri,
    /// QUIC tuning.
    pub quic: QuicConfig,
    /// Client info sent in `x-client`.
    pub info: ClientInfo,
    /// In `auto` mode, how long to stay on TCP+TLS after QUIC failed before trying QUIC again.
    pub fallback_memory: Duration,
}

/// Default for [`EngineConfig::fallback_memory`].
pub const FALLBACK_MEMORY: Duration = Duration::from_secs(600);
/// Grace for streams on the old connection after switching back to QUIC.
const SWITCH_GRACE: Duration = Duration::from_secs(30);

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
    /// The server revoked this device; no more attempts.
    #[error("device revoked by the server")]
    Revoked,
    /// No session within [`SESSION_WAIT`].
    #[error("no session to the server")]
    Unavailable,
    /// The engine was shut down.
    #[error("engine stopped")]
    Stopped,
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
    /// Proxied TCP connections open now.
    pub tcp_streams: usize,
    /// UDP flows open now.
    pub udp_flows: usize,
    /// UDP datagrams dropped (oversize or full queues).
    pub udp_drops: u64,
    /// Sessions established after the first.
    pub reconnects: u64,
    /// The server revoked this device.
    pub revoked: bool,
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum End {
    Revoked,
    Shutdown(Duration),
    Idle,
    Lost(String),
}

/// An authenticated connection.
pub(crate) struct Session {
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) info: SessionInfo,
    /// `quic` or `tls`.
    pub(crate) kind: &'static str,
    /// Frames to send on the control channel.
    pub(crate) control: mpsc::Sender<ControlFrame>,
    /// QUIC only: the endpoint, for rebinding.
    endpoint: Option<Endpoint>,
    /// `GoAway` from the server: code and retry delay.
    go_away: watch::Receiver<Option<(ErrorCode, u64)>>,
    closed: watch::Receiver<bool>,
    // Kept open for the session's lifetime (QUIC: the HTTP/3 control stream).
    _h3_streams: Vec<quinn::SendStream>,
    tasks: Vec<AbortHandle>,
}

impl Session {
    /// Usable for new streams: open and not told to go away.
    pub(crate) fn is_alive(&self) -> bool {
        !*self.closed.borrow() && self.go_away.borrow().is_none()
    }

    async fn ended(&self) -> End {
        let mut go_away = self.go_away.clone();
        tokio::select! {
            e = self.transport.closed() => match e {
                TransportError::ClosedByPeer(ErrorCode::REVOKED) => End::Revoked,
                other => End::Lost(other.to_string()),
            },
            Ok(g) = go_away.wait_for(Option::is_some) => match *g {
                Some((ErrorCode::REVOKED, _)) => End::Revoked,
                Some((ErrorCode::IDLE_TIMEOUT, _)) => End::Idle,
                // Evicted for a newer session of the same device: back off, do not fight it.
                Some((ErrorCode::SESSION_LIMIT, _)) => End::Lost("session limit".into()),
                Some((_, ms)) => End::Shutdown(Duration::from_millis(ms).min(RETRY_AFTER_MAX)),
                None => End::Lost("go away".into()),
            },
        }
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
    pub(crate) current: watch::Sender<Option<Arc<Session>>>,
    connecting: Mutex<()>,
    supervised: AtomicBool,
    supervisor: std::sync::Mutex<Option<AbortHandle>>,
    revoked: AtomicBool,
    stopped: AtomicBool,
    demand: Notify,
    pub(crate) udp: Arc<UdpRegistry>,
    pub(crate) tcp_streams: AtomicUsize,
    sessions_established: AtomicU64,
    /// `auto` mode: QUIC failed, use TCP+TLS until then.
    tls_until: std::sync::Mutex<Option<Instant>>,
}

impl Engine {
    /// Engine for `config`; no connection is made until [`Engine::start`] or first use.
    pub fn new(config: EngineConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                current: watch::Sender::new(None),
                connecting: Mutex::new(()),
                supervised: AtomicBool::new(false),
                supervisor: std::sync::Mutex::new(None),
                revoked: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                demand: Notify::new(),
                udp: Arc::new(UdpRegistry::default()),
                tcp_streams: AtomicUsize::new(0),
                sessions_established: AtomicU64::new(0),
                tls_until: std::sync::Mutex::new(None),
            }),
        }
    }

    /// Keeps a session up in the background from now on (the daemon mode).
    pub fn start(&self) {
        if self.inner.stopped.load(Ordering::Acquire) {
            return;
        }
        if !self.inner.supervised.swap(true, Ordering::AcqRel) {
            let task = tokio::spawn(supervise(self.clone())).abort_handle();
            *self
                .inner
                .supervisor
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(task);
        }
    }

    /// Stops for good: no more reconnects, the session is closed and every stream and flow on
    /// it ends. New connections fail with [`EngineError::Stopped`].
    pub async fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        let supervisor = self
            .inner
            .supervisor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = supervisor {
            task.abort();
        }
        if let Some(session) = self.inner.current.send_replace(None) {
            session.transport.close(ErrorCode::NO_ERROR, b"shutdown");
            if let Some(endpoint) = &session.endpoint {
                let _ = tokio::time::timeout(CLOSE_GRACE, endpoint.wait_idle()).await;
            }
        }
        // Wakes callers waiting for a session.
        self.inner.current.send_replace(None);
    }

    /// One session now, without the supervisor (for `check`).
    pub async fn connect(&self) -> Result<SessionInfo, EngineError> {
        Ok(self.session().await?.info)
    }

    fn live(&self) -> Option<Arc<Session>> {
        self.inner
            .current
            .borrow()
            .as_ref()
            .filter(|s| s.is_alive())
            .cloned()
    }

    fn publish(&self, session: Arc<Session>) {
        // UDP sessions of an older connection are gone on the server; the next datagram of
        // every flow carries its address again.
        self.inner.udp.reset_all();
        self.inner
            .sessions_established
            .fetch_add(1, Ordering::Relaxed);
        self.inner.current.send_replace(Some(session));
    }

    /// The live session. Under the supervisor, waits up to [`SESSION_WAIT`] for one; without
    /// it, connects inline (concurrent callers share the attempt).
    pub(crate) async fn session(&self) -> Result<Arc<Session>, EngineError> {
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(EngineError::Stopped);
        }
        if self.inner.revoked.load(Ordering::Acquire) {
            return Err(EngineError::Revoked);
        }
        if let Some(session) = self.live() {
            return Ok(session);
        }
        if !self.inner.supervised.load(Ordering::Acquire) {
            let _guard = self.inner.connecting.lock().await;
            if let Some(session) = self.live() {
                return Ok(session);
            }
            let session = Arc::new(establish(self).await?);
            if self.inner.stopped.load(Ordering::Acquire) {
                session.transport.close(ErrorCode::NO_ERROR, b"shutdown");
                return Err(EngineError::Stopped);
            }
            self.publish(session.clone());
            return Ok(session);
        }
        self.inner.demand.notify_one();
        let mut rx = self.inner.current.subscribe();
        let wait = async {
            loop {
                if self.inner.stopped.load(Ordering::Acquire) {
                    return Err(EngineError::Stopped);
                }
                if self.inner.revoked.load(Ordering::Acquire) {
                    return Err(EngineError::Revoked);
                }
                if let Some(session) = rx.borrow_and_update().as_ref().filter(|s| s.is_alive()) {
                    return Ok(session.clone());
                }
                if rx.changed().await.is_err() {
                    return Err(EngineError::Unavailable);
                }
            }
        };
        tokio::time::timeout(SESSION_WAIT, wait)
            .await
            .unwrap_or(Err(EngineError::Unavailable))
    }

    /// Moves the QUIC socket to a fresh local port after a WAN address change; connection
    /// migration keeps the session and its calls.
    pub fn rebind(&self) -> Result<(), EngineError> {
        let Some(endpoint) = self.live().and_then(|s| s.endpoint.clone()) else {
            return Ok(());
        };
        let bind: SocketAddr = match endpoint.local_addr() {
            Ok(SocketAddr::V6(_)) => "[::]:0",
            _ => "0.0.0.0:0",
        }
        .parse()
        .expect("literal address");
        quic::rebind(&endpoint, bind).map_err(|e| EngineError::Connect(e.to_string()))?;
        log::info!("rebound the QUIC socket");
        Ok(())
    }

    /// Current state.
    pub async fn status(&self) -> Status {
        let live = self.live();
        Status {
            connected: live.is_some(),
            transport: live.as_ref().map(|s| s.kind),
            session: live.as_ref().map(|s| s.info),
            stats: live
                .as_ref()
                .map_or_else(TransportStats::default, |s| s.transport.stats()),
            tcp_streams: self.inner.tcp_streams.load(Ordering::Relaxed),
            udp_flows: self.inner.udp.len(),
            udp_drops: self.inner.udp.drops.load(Ordering::Relaxed),
            reconnects: self
                .inner
                .sessions_established
                .load(Ordering::Relaxed)
                .saturating_sub(1),
            revoked: self.inner.revoked.load(Ordering::Acquire),
        }
    }
}

/// Keeps one session up until the device is revoked.
async fn supervise(engine: Engine) {
    let inner = &engine.inner;
    let mut failures = 0u32;
    loop {
        match establish(&engine).await {
            Ok(session) => {
                failures = 0;
                let mut session = Arc::new(session);
                engine.publish(session.clone());
                let end = loop {
                    let probe_at = engine.probe_at(&session);
                    let probe = async {
                        match probe_at {
                            Some(at) => tokio::time::sleep_until(at.into()).await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        end = session.ended() => break end,
                        () = probe => {
                            match establish_quic(&inner.config, inner.udp.clone()).await {
                                Ok(quic) => {
                                    log::info!("QUIC works again; switching back from TCP+TLS");
                                    *inner.tls_until.lock().unwrap_or_else(|e| e.into_inner()) = None;
                                    let old = std::mem::replace(&mut session, Arc::new(quic));
                                    engine.publish(session.clone());
                                    // Streams still on the old connection get a grace period.
                                    tokio::spawn(async move {
                                        tokio::time::sleep(SWITCH_GRACE).await;
                                        old.transport.close(ErrorCode::NO_ERROR, b"switched");
                                    });
                                }
                                Err(e) => {
                                    log::debug!("QUIC probe failed: {e}");
                                    engine.remember_tls();
                                }
                            }
                        }
                    }
                };
                // New streams wait for the next session; open ones keep the old connection.
                inner.current.send_if_modified(|current| {
                    let same = current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &session));
                    if same {
                        *current = None;
                    }
                    same
                });
                drop(session);
                match end {
                    End::Revoked => {
                        log::error!("the server revoked this device; not reconnecting");
                        inner.revoked.store(true, Ordering::Release);
                        inner.current.send_replace(None);
                        return;
                    }
                    End::Shutdown(retry) => {
                        log::info!(
                            "server going away, reconnecting in {} ms",
                            retry.as_millis()
                        );
                        tokio::time::sleep(retry).await;
                        continue;
                    }
                    End::Idle => {
                        log::info!("session idle; reconnecting on demand");
                        inner.demand.notified().await;
                        continue;
                    }
                    End::Lost(reason) => log::warn!("session lost: {reason}"),
                }
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                log::warn!("connecting failed (attempt {failures}): {e}");
            }
        }
        tokio::time::sleep(backoff(failures)).await;
    }
}

/// `0.5 s · 2^n` capped at 30 s, scaled by a random factor in [0.5, 1).
fn backoff(failures: u32) -> Duration {
    let base = BACKOFF_MIN
        .saturating_mul(1 << failures.min(16))
        .min(BACKOFF_MAX);
    let mut seed = [0u8; 2];
    let _ = getrandom::fill(&mut seed);
    let jitter = 0.5 + f64::from(u16::from_le_bytes(seed)) / f64::from(u16::MAX) / 2.0;
    base.mul_f64(jitter.min(0.999))
}

/// Connects over the transport the URI asks for and runs the auth exchange.
async fn establish(engine: &Engine) -> Result<Session, EngineError> {
    let (config, udp) = (&engine.inner.config, engine.inner.udp.clone());
    match config.uri.transport {
        TransportMode::Tls => establish_tls(config, udp).await,
        TransportMode::Quic => establish_quic(config, udp).await,
        TransportMode::Auto => {
            if engine.tls_remembered() {
                return establish_tls(config, udp).await;
            }
            match establish_quic(config, udp.clone()).await {
                Ok(session) => Ok(session),
                // Only a transport failure says QUIC is blocked; a rejection would repeat on TCP.
                Err(e @ EngineError::Handshake(_)) => Err(e),
                Err(e) => {
                    log::warn!("QUIC failed ({e}); falling back to TCP+TLS");
                    engine.remember_tls();
                    establish_tls(config, udp).await
                }
            }
        }
    }
}

impl Engine {
    fn tls_remembered(&self) -> bool {
        let until = *self
            .inner
            .tls_until
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        until.is_some_and(|t| Instant::now() < t)
    }

    fn remember_tls(&self) {
        let until = Instant::now() + self.inner.config.fallback_memory;
        *self
            .inner
            .tls_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(until);
    }

    /// When to try QUIC again from a fallback session; `None` if not in `auto` fallback.
    fn probe_at(&self, session: &Session) -> Option<Instant> {
        if self.inner.config.uri.transport != TransportMode::Auto || session.kind != "tls" {
            return None;
        }
        let until = *self
            .inner
            .tls_until
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Some(until.unwrap_or_else(Instant::now))
    }
}

/// One session over the given transport, for `partizan check`; returns it with its setup time.
pub async fn check_transport(
    mut config: EngineConfig,
    mode: TransportMode,
) -> Result<(SessionInfo, Duration), EngineError> {
    config.uri.transport = mode;
    let started = Instant::now();
    let udp = Arc::new(UdpRegistry::default());
    let session = match mode {
        TransportMode::Tls => establish_tls(&config, udp).await?,
        _ => establish_quic(&config, udp).await?,
    };
    let elapsed = started.elapsed();
    session.transport.close(ErrorCode::NO_ERROR, b"check");
    Ok((session.info, elapsed))
}

/// QUIC with the HTTP/3 auth exchange on the first bidi stream.
async fn establish_quic(
    config: &EngineConfig,
    udp: Arc<UdpRegistry>,
) -> Result<Session, EngineError> {
    let uri = &config.uri;
    require_supported_auth(uri)?;
    let addr = resolve(&uri.host, uri.port).await?;
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("literal address");
    let endpoint = transport::boring_quic::client_endpoint(
        bind,
        ServerVerification::from_uri(uri),
        &config.quic,
    )
    .map_err(|e| EngineError::Connect(e.to_string()))?;
    let started = Instant::now();
    let transport = tokio::time::timeout(
        QUIC_HANDSHAKE_TIMEOUT,
        quic::connect(&endpoint, addr, uri.server_name()),
    )
    .await
    .map_err(|_| EngineError::Connect(format!("QUIC handshake with {addr} timed out")))?
    .map_err(|e| EngineError::Connect(e.to_string()))?;
    let conn = transport.connection().clone();
    let auth = async {
        let mut h3_control = conn.open_uni().await.map_err(io)?;
        let mut seed = [0; 8];
        getrandom::fill(&mut seed).map_err(|e| EngineError::Connect(e.to_string()))?;
        h3_control
            .write_all(&client_control_stream_seeded(u64::from_ne_bytes(seed)))
            .await
            .map_err(io)?;
        let mut encoder = conn.open_uni().await.map_err(io)?;
        encoder.write_all(&[2]).await.map_err(io)?;
        let mut decoder = conn.open_uni().await.map_err(io)?;
        decoder.write_all(&[3]).await.map_err(io)?;
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
                return Ok((established, vec![h3_control, encoder, decoder], send, recv));
            }
        }
    };
    let (established, h3_control, send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, auth)
        .await
        .map_err(|_| EngineError::Handshake(HandshakeError::Timeout))??;
    log::info!(
        "session up via QUIC to {addr} in {} ms",
        started.elapsed().as_millis()
    );
    let control = Arc::new(QuicControl::new(send, recv, established.leftover));
    Ok(start_session(
        Arc::new(transport),
        control,
        established.session,
        "quic",
        Some(endpoint),
        h3_control,
        udp,
    ))
}

/// TCP+TLS with the HTTP/1.1 `Upgrade` exchange, then the mux.
async fn establish_tls(
    config: &EngineConfig,
    udp: Arc<UdpRegistry>,
) -> Result<Session, EngineError> {
    let uri = &config.uri;
    require_supported_auth(uri)?;
    let addr = resolve(&uri.host, uri.port).await?;
    // Chrome's ClientHello on BoringSSL; it offers h2 and http/1.1, our server picks http/1.1.
    let started = Instant::now();
    let mut stream = tokio::time::timeout(
        TLS_CONNECT_TIMEOUT,
        transport::chrome::connect(addr, uri.server_name(), ServerVerification::from_uri(uri)),
    )
    .await
    .map_err(|_| EngineError::Connect(format!("TLS connect to {addr} timed out")))?
    .map_err(|e| EngineError::Connect(e.to_string()))?;
    if stream.ssl().selected_alpn_protocol() != Some(ALPN_HTTP11) {
        return Err(EngineError::Connect(
            "server did not select http/1.1".into(),
        ));
    }
    let auth = async {
        let (mut handshake, request) =
            ClientHandshake::start(AuthTransport::Tls, uri, &config.info, Instant::now())?;
        stream.write_all(&request).await.map_err(io)?;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.map_err(io)?;
            if n == 0 {
                return Err(EngineError::Handshake(HandshakeError::Rejected));
            }
            if let Some(established) = handshake.handle_input(&buf[..n])? {
                return Ok(established);
            }
        }
    };
    let established = tokio::time::timeout(HANDSHAKE_TIMEOUT, auth)
        .await
        .map_err(|_| EngineError::Handshake(HandshakeError::Timeout))??;
    log::info!(
        "session up via TCP+TLS to {addr} in {} ms",
        started.elapsed().as_millis()
    );
    let mux = MuxTransport::new(stream, Role::Client, &established.leftover);
    Ok(start_session(
        Arc::new(mux.clone()),
        Arc::new(mux),
        established.session,
        "tls",
        None,
        Vec::new(),
        udp,
    ))
}

// Until C24 authenticates the server by HMAC, Web PKI alone would accept the
// masquerade site's real certificate and send our device token to that site.
fn require_supported_auth(uri: &ConnectionUri) -> Result<(), EngineError> {
    if uri.passthrough.is_some() {
        return Err(EngineError::Connect(
            "passthrough mark authentication is not implemented".into(),
        ));
    }
    Ok(())
}

/// Starts the control channel and datagram tasks of a fresh session.
fn start_session(
    transport: Arc<dyn Transport>,
    control_channel: Arc<dyn ControlChannel>,
    info: SessionInfo,
    kind: &'static str,
    endpoint: Option<Endpoint>,
    h3_streams: Vec<quinn::SendStream>,
    udp: Arc<UdpRegistry>,
) -> Session {
    log::info!("sid {:x}, caps {:x}", info.sid, info.caps.0);
    let (control, control_rx) = mpsc::channel(64);
    let (go_away_tx, go_away) = watch::channel(None);
    let (closed_tx, closed) = watch::channel(false);
    let watcher = transport.clone();
    let tasks = vec![
        tokio::spawn(write_control(control_channel.clone(), control_rx)).abort_handle(),
        tokio::spawn(read_control(control_channel, udp.clone(), go_away_tx)).abort_handle(),
        tokio::spawn(read_datagrams(transport.clone(), udp)).abort_handle(),
        tokio::spawn(async move {
            watcher.closed().await;
            closed_tx.send_replace(true);
        })
        .abort_handle(),
    ];
    Session {
        transport,
        info,
        kind,
        control,
        endpoint,
        go_away,
        closed,
        _h3_streams: h3_streams,
        tasks,
    }
}

/// Sends control frames.
async fn write_control(channel: Arc<dyn ControlChannel>, mut frames: mpsc::Receiver<ControlFrame>) {
    while let Some(frame) = frames.recv().await {
        let mut body = Vec::new();
        if frame.encode(&mut body).is_ok() && channel.send(body).await.is_err() {
            return;
        }
    }
}

/// Handles the server's control frames.
async fn read_control(
    channel: Arc<dyn ControlChannel>,
    udp: Arc<UdpRegistry>,
    go_away: watch::Sender<Option<(ErrorCode, u64)>>,
) {
    let mut frames = ControlReader::default();
    while let Some(bytes) = channel.recv().await {
        let Ok(parsed) = frames.push(&bytes) else {
            return;
        };
        for frame in parsed {
            match frame {
                ControlFrame::UdpClose { session_id, reason } => {
                    log::debug!("server closed UDP session {session_id} (reason {reason})");
                    udp.server_closed(session_id);
                }
                ControlFrame::GoAway {
                    code,
                    retry_after_ms,
                } => {
                    log::info!("GoAway {code:?}, retry after {retry_after_ms} ms");
                    go_away.send_replace(Some((code, retry_after_ms)));
                }
                _ => {}
            }
        }
    }
}

/// Hands incoming datagrams to their UDP flows.
async fn read_datagrams(transport: Arc<dyn Transport>, udp: Arc<UdpRegistry>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_passthrough_never_resolves_or_sends_credentials() {
        let uri = ConnectionUri {
            device_id: proto::auth::DeviceId([7; 16]),
            token: proto::auth::Token::from_bytes([9; 32]),
            host: "invalid host".into(),
            port: 443,
            sni: None,
            path: "/auth".into(),
            pin: None,
            transport: TransportMode::Tls,
            insecure: true,
            passthrough: Some(proto::auth::Passthrough {
                public_key: [1; 32],
                short_id: [2; 8],
            }),
        };
        let config = EngineConfig {
            uri,
            quic: QuicConfig::default(),
            info: ClientInfo::new("test", "test"),
            fallback_memory: FALLBACK_MEMORY,
        };
        for mode in [TransportMode::Tls, TransportMode::Quic] {
            let error = check_transport(config.clone(), mode).await.unwrap_err();
            assert_eq!(
                error,
                EngineError::Connect("passthrough mark authentication is not implemented".into())
            );
        }
    }

    #[test]
    fn backoff_grows_with_jitter_and_caps() {
        for _ in 0..100 {
            let first = backoff(0);
            assert!(first >= BACKOFF_MIN / 2 && first < BACKOFF_MIN, "{first:?}");
            let third = backoff(2);
            assert!(
                third >= Duration::from_secs(1) && third < Duration::from_secs(2),
                "{third:?}"
            );
            let late = backoff(30);
            assert!(late >= BACKOFF_MAX / 2 && late < BACKOFF_MAX, "{late:?}");
        }
    }
}

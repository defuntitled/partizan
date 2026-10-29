//! Mobile facade over the client: one tunnel at a time, driven over UniFFI (Kotlin now, Swift
//! later).
//!
//! The platform opens the TUN interface and passes its fd to [`start`]; the engine, the TUN
//! stack and their runtime live here until [`stop`]. State changes reach the platform through
//! a [`StatusListener`]. The token travels only inside the connection URI and never comes back
//! in a returned string or a log line.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use client_core::{Engine, EngineConfig, EngineError, FALLBACK_MEMORY};
use proto::auth::{ClientInfo, ConnectionUri, TransportMode};
use transport::QuicConfig;
use tun::{Diagnostics, Direct, FdDevice, IpNet, Split};

uniffi::setup_scaffolding!();

/// How often the status is refreshed and, if changed, sent to the listener.
const STATUS_TICK: Duration = Duration::from_millis(500);
/// Smallest MTU accepted: the IPv4 minimum every host must take.
const MIN_MTU: u16 = 576;
/// How long `stop` waits for the runtime's tasks to finish.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Launch settings, assembled from a server profile on the platform side.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VpnConfig {
    /// `partizan://…` connection link, token included.
    pub uri: String,
    /// Split tunneling rules.
    pub split: SplitConfig,
    /// MTU of the TUN interface, as set on the platform's interface builder.
    pub mtu: u16,
}

/// Which traffic goes through the tunnel.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SplitConfig {
    /// How `routes` is read.
    pub mode: SplitMode,
    /// Addresses and CIDR networks: `99.84.0.0/16`, `203.0.113.7`, `2606:4700::/32`.
    pub routes: Vec<String>,
}

/// Meaning of the listed routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SplitMode {
    /// Only the listed networks go through the tunnel.
    Include,
    /// Everything but the listed networks goes through the tunnel.
    Exclude,
}

/// Tunnel state, as the main screen shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VpnState {
    /// Not started.
    Idle,
    /// Started, no session yet.
    Connecting,
    /// A session is up.
    Connected,
    /// The session was lost; the engine is reconnecting.
    Reconnecting,
    /// The server revoked this device; no more attempts.
    Revoked,
    /// The tunnel stopped working (`error` says why); `stop` cleans up.
    Error,
}

/// Status snapshot for the UI.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct VpnStatus {
    /// State.
    pub state: VpnState,
    /// `quic` or `tls` while connected.
    pub transport: Option<String>,
    /// Smoothed round-trip time while connected, if the transport measures it (QUIC does).
    pub rtt_ms: Option<u32>,
    /// Payload bytes sent through the tunnel since start.
    pub tx_bytes: u64,
    /// Payload bytes received through the tunnel since start.
    pub rx_bytes: u64,
    /// Sessions established after the first.
    pub reconnects: u64,
    /// Why the state is `Error`.
    pub error: Option<String>,
}

impl VpnStatus {
    fn idle() -> Self {
        Self {
            state: VpnState::Idle,
            transport: None,
            rtt_ms: None,
            tx_bytes: 0,
            rx_bytes: 0,
            reconnects: 0,
            error: None,
        }
    }
}

/// Result of [`check_uri`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CheckResult {
    /// Server host from the link, a default name for the profile.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Session setup time over QUIC, if QUIC works.
    pub quic_ms: Option<u32>,
    /// Session setup time over TCP+TLS, if it works.
    pub tls_ms: Option<u32>,
}

/// Stack counters for the diagnostics screen; all zero while profiling is off.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct StackMetrics {
    /// Packets per second, both directions, since profiling was switched on.
    pub packets_per_sec: f64,
    /// Packets read from the interface.
    pub packets_in: u64,
    /// Packets written to the interface.
    pub packets_out: u64,
    /// Packets dropped.
    pub dropped: u64,
    /// Median stack time per packet, microseconds.
    pub packet_time_p50_us: u64,
    /// 99th percentile of the same.
    pub packet_time_p99_us: u64,
    /// Packets waiting for the interface.
    pub queue_depth: u64,
    /// Highest queue depth seen.
    pub queue_peak: u64,
    /// Open TCP connections.
    pub tcp_connections: u64,
    /// Open UDP flows.
    pub udp_flows: u64,
    /// Share of busy time spent in the stack rather than interface I/O, `0.0..=1.0`.
    pub stack_share: f64,
}

/// Why a call failed. Messages never contain the token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum VpnError {
    /// The connection link is malformed.
    #[error("invalid link: {reason}")]
    InvalidUri {
        /// What is wrong with it.
        reason: String,
    },
    /// A setting is out of range or a route does not parse.
    #[error("invalid settings: {reason}")]
    InvalidConfig {
        /// Which one.
        reason: String,
    },
    /// The TUN fd is unusable.
    #[error("TUN interface: {reason}")]
    Tun {
        /// Why.
        reason: String,
    },
    /// A tunnel is already running; `stop` it first.
    #[error("already running")]
    AlreadyRunning,
    /// The server cannot be reached over the configured transport.
    #[error("server unreachable: {reason}")]
    Unreachable {
        /// What each transport reported.
        reason: String,
    },
}

/// Receives every status change. Called from a background thread: hand the status over to the
/// UI thread and return.
#[uniffi::export(foreign)]
pub trait StatusListener: Send + Sync {
    /// The status changed.
    fn on_status(&self, status: VpnStatus);
}

struct Running {
    runtime: tokio::runtime::Runtime,
    engine: Engine,
    shared: Arc<Shared>,
    listener: Arc<dyn StatusListener>,
}

/// State shared between the status task and the calls.
struct Shared {
    status: Mutex<VpnStatus>,
    /// Set when the TUN stack ends on its own.
    failure: Mutex<Option<String>>,
    split: Arc<Split>,
}

static VPN: Mutex<Option<Running>> = Mutex::new(None);
/// Outlives runs so the toggles can be set before `start`.
static DIAGNOSTICS: LazyLock<Arc<Diagnostics>> = LazyLock::new(Arc::default);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Takes the already open TUN fd and brings the tunnel up. Returns at once; progress arrives
/// through `listener`. The fd belongs to the tunnel from here on (the platform detaches it) and
/// is closed by [`stop`], or right away if the call fails after checking it.
#[uniffi::export]
pub fn start(
    tun_fd: i32,
    config: VpnConfig,
    listener: Arc<dyn StatusListener>,
) -> Result<(), VpnError> {
    let uri = ConnectionUri::parse(&config.uri).map_err(|e| VpnError::InvalidUri {
        reason: e.to_string(),
    })?;
    let split = split_config(&config.split)?;
    if config.mtu < MIN_MTU {
        return Err(VpnError::InvalidConfig {
            reason: format!("MTU {} is below {MIN_MTU}", config.mtu),
        });
    }
    let mut vpn = lock(&VPN);
    if vpn.is_some() {
        return Err(VpnError::AlreadyRunning);
    }
    let fd = take_fd(tun_fd)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("partizan")
        .enable_all()
        .build()
        .map_err(|e| VpnError::Tun {
            reason: format!("runtime: {e}"),
        })?;
    let context = runtime.enter();
    let device = FdDevice::new(fd).map_err(|e| VpnError::Tun {
        reason: e.to_string(),
    })?;
    let engine = Engine::new(engine_config(uri));
    engine.start();
    let shared = Arc::new(Shared {
        status: Mutex::new(VpnStatus {
            state: VpnState::Connecting,
            ..VpnStatus::idle()
        }),
        failure: Mutex::new(None),
        split: Arc::new(Split::new(&split)),
    });
    let stack = tun::run(
        device,
        engine.clone(),
        // The app is excluded from its own VPN, so its sockets already bypass the interface.
        Direct::default(),
        shared.split.clone(),
        tun::Config {
            mtu: usize::from(config.mtu),
            ..tun::Config::default()
        },
        DIAGNOSTICS.clone(),
    );
    let on_end = shared.clone();
    runtime.spawn(async move {
        let reason = match stack.await {
            Ok(()) => "interface closed".to_owned(),
            Err(e) => e.to_string(),
        };
        log::warn!("TUN stack ended: {reason}");
        *lock(&on_end.failure) = Some(reason);
    });
    runtime.spawn(report(engine.clone(), shared.clone(), listener.clone()));
    drop(context);
    *vpn = Some(Running {
        runtime,
        engine,
        shared,
        listener,
    });
    Ok(())
}

/// Stops the tunnel: closes the session, the stack and the TUN fd. Does nothing if not
/// running. The listener gets a final `Idle`. Called from inside a listener callback, it
/// returns before the shutdown completes.
#[uniffi::export]
pub fn stop() {
    let Some(running) = lock(&VPN).take() else {
        return;
    };
    // `block_on` cannot nest in a runtime thread: shut down from a thread of its own.
    let shutdown = std::thread::spawn(move || {
        let Running {
            runtime,
            engine,
            listener,
            ..
        } = running;
        runtime.block_on(engine.shutdown());
        runtime.shutdown_timeout(STOP_TIMEOUT);
        listener.on_status(VpnStatus::idle());
    });
    if tokio::runtime::Handle::try_current().is_err() {
        let _ = shutdown.join();
    }
}

/// Current status, at most one status tick old.
#[uniffi::export]
pub fn status() -> VpnStatus {
    match &*lock(&VPN) {
        Some(running) => lock(&running.shared.status).clone(),
        None => VpnStatus::idle(),
    }
}

/// Parses `uri` and tries both transports without bringing the tunnel up. Blocks for up to
/// some seconds: call it off the UI thread. With `transport=auto` one working transport is
/// enough.
#[uniffi::export]
pub fn check_uri(uri: String) -> Result<CheckResult, VpnError> {
    let uri = ConnectionUri::parse(&uri).map_err(|e| VpnError::InvalidUri {
        reason: e.to_string(),
    })?;
    let mode = uri.transport;
    let (host, port) = (uri.host.clone(), uri.port);
    let config = engine_config(uri);
    // A thread of its own, so a caller inside a runtime does not nest `block_on`.
    let (quic, tls) = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| EngineError::Connect(format!("runtime: {e}")))?;
        let try_one =
            |transport| runtime.block_on(client_core::check_transport(config.clone(), transport));
        Ok::<_, EngineError>((try_one(TransportMode::Quic), try_one(TransportMode::Tls)))
    })
    .join()
    .unwrap_or_else(|_| Err(EngineError::Connect("check failed".into())))
    .map_err(|e| VpnError::Unreachable {
        reason: e.to_string(),
    })?;
    let usable = match mode {
        TransportMode::Auto => quic.is_ok() || tls.is_ok(),
        TransportMode::Quic => quic.is_ok(),
        TransportMode::Tls => tls.is_ok(),
    };
    let millis = |r: &Result<(_, Duration), EngineError>| {
        r.as_ref()
            .ok()
            .map(|(_, elapsed)| u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX))
    };
    if !usable {
        let describe = |r: &Result<_, EngineError>| match r {
            Ok(_) => "ok".to_owned(),
            Err(e) => e.to_string(),
        };
        return Err(VpnError::Unreachable {
            reason: format!("QUIC: {}; TCP+TLS: {}", describe(&quic), describe(&tls)),
        });
    }
    Ok(CheckResult {
        host,
        port,
        quic_ms: millis(&quic),
        tls_ms: millis(&tls),
    })
}

/// Switches stack profiling and the verbose stack log on the fly, running or not.
#[uniffi::export]
pub fn set_diagnostics(profiling: bool, verbose_log: bool) {
    DIAGNOSTICS.set(profiling, verbose_log);
}

/// Stack counters for the diagnostics screen.
#[uniffi::export]
pub fn stack_metrics() -> StackMetrics {
    let m = DIAGNOSTICS.metrics();
    StackMetrics {
        packets_per_sec: m.packets_per_sec(),
        packets_in: m.packets_in,
        packets_out: m.packets_out,
        dropped: m.dropped,
        packet_time_p50_us: m.packet_time_p50.as_micros() as u64,
        packet_time_p99_us: m.packet_time_p99.as_micros() as u64,
        queue_depth: m.queue_depth,
        queue_peak: m.queue_peak,
        tcp_connections: m.tcp_connections,
        udp_flows: m.udp_flows,
        stack_share: m.stack_share(),
    }
}

fn engine_config(uri: ConnectionUri) -> EngineConfig {
    EngineConfig {
        uri,
        quic: QuicConfig::default(),
        info: ClientInfo::new(std::env::consts::OS, env!("CARGO_PKG_VERSION")),
        fallback_memory: FALLBACK_MEMORY,
    }
}

fn split_config(config: &SplitConfig) -> Result<tun::SplitConfig, VpnError> {
    let routes = config
        .routes
        .iter()
        .map(|route| {
            route
                .trim()
                .parse::<IpNet>()
                .map_err(|_| VpnError::InvalidConfig {
                    reason: format!("route {route:?} is not an address or CIDR network"),
                })
        })
        .collect::<Result<_, _>>()?;
    let mode = match config.mode {
        SplitMode::Include => tun::SplitMode::Include,
        SplitMode::Exclude => tun::SplitMode::Exclude,
    };
    Ok(tun::SplitConfig { mode, routes })
}

/// Checks `fd` and takes ownership of it, switching it to non-blocking mode.
fn take_fd(fd: RawFd) -> Result<OwnedFd, VpnError> {
    let invalid = |e: std::io::Error| VpnError::Tun {
        reason: format!("fd {fd}: {e}"),
    };
    if fd < 0 {
        return Err(invalid(std::io::Error::from_raw_os_error(libc::EBADF)));
    }
    // SAFETY: `fcntl` on an integer touches no memory; a closed fd fails with EBADF.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(invalid(std::io::Error::last_os_error()));
    }
    // SAFETY: the fd is open (checked above) and the caller hands it over to us.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: as above; only the status flags change.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(invalid(std::io::Error::last_os_error()));
    }
    Ok(owned)
}

/// Refreshes the status every tick and sends changes to the listener.
async fn report(engine: Engine, shared: Arc<Shared>, listener: Arc<dyn StatusListener>) {
    let mut connected_once = false;
    let mut last: Option<VpnStatus> = None;
    let mut tick = tokio::time::interval(STATUS_TICK);
    loop {
        tick.tick().await;
        let core = engine.status().await;
        connected_once |= core.connected;
        let failure = lock(&shared.failure).clone();
        let status = to_status(&core, connected_once, failure, &shared.split.stats());
        *lock(&shared.status) = status.clone();
        if last.as_ref() != Some(&status) {
            listener.on_status(status.clone());
            last = Some(status);
        }
    }
}

fn to_status(
    core: &client_core::Status,
    connected_once: bool,
    failure: Option<String>,
    traffic: &tun::SplitStats,
) -> VpnStatus {
    let state = if failure.is_some() {
        VpnState::Error
    } else if core.revoked {
        VpnState::Revoked
    } else if core.connected {
        VpnState::Connected
    } else if connected_once {
        VpnState::Reconnecting
    } else {
        VpnState::Connecting
    };
    let connected = state == VpnState::Connected;
    VpnStatus {
        state,
        transport: core.transport.filter(|_| connected).map(str::to_owned),
        // TCP+TLS does not measure RTT and reports zero: unknown, not instant.
        rtt_ms: (connected && !core.stats.rtt.is_zero())
            .then(|| u32::try_from(core.stats.rtt.as_millis()).unwrap_or(u32::MAX)),
        tx_bytes: traffic.tunnel_sent,
        rx_bytes: traffic.tunnel_received,
        reconnects: core.reconnects,
        error: failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(connected: bool, revoked: bool) -> client_core::Status {
        client_core::Status {
            connected,
            transport: connected.then_some("quic"),
            session: None,
            stats: transport::TransportStats {
                rtt: Duration::from_millis(42),
                ..Default::default()
            },
            tcp_streams: 0,
            udp_flows: 0,
            udp_drops: 0,
            reconnects: 0,
            revoked,
        }
    }

    #[test]
    fn states_follow_the_engine() {
        let t = tun::SplitStats::default();
        let s = |c, once, failure: Option<&str>| {
            to_status(&core(c, false), once, failure.map(str::to_owned), &t).state
        };
        assert_eq!(s(false, false, None), VpnState::Connecting);
        assert_eq!(s(true, true, None), VpnState::Connected);
        assert_eq!(s(false, true, None), VpnState::Reconnecting);
        assert_eq!(s(true, true, Some("closed")), VpnState::Error);
        assert_eq!(
            to_status(&core(false, true), true, None, &t).state,
            VpnState::Revoked
        );
        let up = to_status(&core(true, false), true, None, &t);
        assert_eq!(
            (up.transport.as_deref(), up.rtt_ms),
            (Some("quic"), Some(42))
        );
        let mut tls = core(true, false);
        tls.stats.rtt = Duration::ZERO;
        assert_eq!(
            to_status(&tls, true, None, &t).rtt_ms,
            None,
            "unmeasured RTT"
        );
        let down = to_status(&core(false, false), true, None, &t);
        assert_eq!((down.transport, down.rtt_ms), (None, None));
    }

    #[test]
    fn routes_are_checked() {
        let config = |routes: &[&str]| SplitConfig {
            mode: SplitMode::Include,
            routes: routes.iter().map(|s| s.to_string()).collect(),
        };
        let ok = split_config(&config(&[
            " 99.84.0.0/16",
            "203.0.113.7 ",
            "2606:4700::/32",
        ]));
        assert_eq!(ok.unwrap().routes.len(), 3);
        assert!(matches!(
            split_config(&config(&["99.84.0.0/16", "nonsense"])),
            Err(VpnError::InvalidConfig { reason }) if reason.contains("nonsense")
        ));
    }

    #[test]
    fn bad_fds_are_refused() {
        assert!(matches!(take_fd(-1), Err(VpnError::Tun { .. })));
        // Far above any open descriptor.
        assert!(matches!(take_fd(1_000_000), Err(VpnError::Tun { .. })));
    }
}

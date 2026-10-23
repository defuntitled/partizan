//! partizan server: accepts device sessions over QUIC, authenticates them against the
//! registry and opens their TCP connections from the server's address.

pub mod config;
pub mod dial;
pub mod egress;
pub mod proxy;
pub mod registry;
pub mod sessions;
pub mod udp;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{LookupIpStrategy, ResolveHosts};
use proto::ControlFrame;
use proto::auth::{
    self, AuthRequest, Caps, DataFrameReader, HANDSHAKE_TIMEOUT, ServerPolicy,
    Transport as AuthTransport, encode_data_frame,
};
use proto::control::ControlReader;
use quinn::{Endpoint, Incoming};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use transport::Transport;
use transport::quic::{self, QuicTransport};
use transport::tls::{self, ALPN_H3};

use crate::config::{Config, TlsMode};
use crate::egress::EgressPolicy;
use crate::registry::Registry;
use crate::sessions::{Session, Sessions};
use crate::udp::{UdpLimits, UdpNat};

/// Largest UDP datagram payload we tell clients to send.
const UDP_MAX: u32 = 1200;

/// Server startup failure.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Bad or unusable configuration.
    #[error("config: {0}")]
    Config(String),
    /// Socket or file error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Counters exported as metrics.
#[derive(Debug, Default)]
pub struct Metrics {
    /// UDP replies larger than the client's datagram limit.
    pub udp_oversize_drops: AtomicU64,
    /// Undecodable datagrams, or a new UDP session without a destination.
    pub udp_malformed_drops: AtomicU64,
    /// Datagrams to destinations the egress policy refuses.
    pub udp_denied_drops: AtomicU64,
    /// QUIC connections accepted (authenticated or not).
    pub connections: AtomicU64,
}

impl Metrics {
    /// Current value of a counter.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Shared state for all connections.
pub struct State {
    registry: RwLock<Arc<Registry>>,
    devices_path: PathBuf,
    policy: ServerPolicy,
    /// Egress policy for dialed targets.
    pub egress: EgressPolicy,
    /// DNS resolver for target names.
    pub resolver: TokioResolver,
    /// Live sessions.
    pub sessions: Sessions,
    /// Counters.
    pub metrics: Metrics,
    udp: UdpLimits,
    udp_per_device: Mutex<HashMap<auth::DeviceId, Arc<AtomicUsize>>>,
}

impl State {
    /// Current registry.
    pub fn registry(&self) -> Arc<Registry> {
        self.registry
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Shared UDP session counter of a device.
    fn udp_counter(&self, device: auth::DeviceId) -> Arc<AtomicUsize> {
        let mut map = self
            .udp_per_device
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.retain(|_, c| Arc::strong_count(c) > 1 || c.load(Ordering::Relaxed) > 0);
        map.entry(device).or_default().clone()
    }

    /// Re-reads the registry file; on error the old registry stays.
    pub fn reload_registry(&self) -> Result<usize, String> {
        let registry = Registry::load(&self.devices_path)?;
        let count = registry.len();
        *self.registry.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(registry);
        Ok(count)
    }
}

/// Bound server, ready to [`Server::run`].
pub struct Server {
    endpoint: Endpoint,
    state: Arc<State>,
    pin: [u8; 32],
}

impl Server {
    /// Loads certificates and the registry and binds UDP.
    pub async fn bind(config: Config) -> Result<Self, ServerError> {
        let (chain, key) = load_certificate(&config)?;
        let pin = tls::spki_pin(&chain[0])
            .ok_or_else(|| ServerError::Config("certificate without SPKI".into()))?;
        let tls = tls::server_config(chain, key, &[ALPN_H3])
            .map_err(|e| ServerError::Config(e.to_string()))?;
        let endpoint = quic::server_endpoint(config.server.listen, tls, &config.quic)?;
        let registry = Registry::load(&config.server.devices).map_err(ServerError::Config)?;
        let mut resolver =
            TokioResolver::builder_tokio().map_err(|e| ServerError::Config(e.to_string()))?;
        let opts = resolver.options_mut();
        opts.ip_strategy = LookupIpStrategy::Ipv6AndIpv4;
        opts.use_hosts_file = ResolveHosts::Always;
        opts.timeout = config.resolver.timeout;
        opts.attempts = config.resolver.attempts;
        let resolver = resolver
            .build()
            .map_err(|e| ServerError::Config(e.to_string()))?;
        let state = State {
            registry: RwLock::new(Arc::new(registry)),
            devices_path: config.server.devices,
            policy: ServerPolicy {
                auth_path: config.server.auth_path,
                caps: Caps::ALL,
                udp_max: UDP_MAX,
            },
            egress: EgressPolicy::new(config.egress.deny_private, config.egress.allow),
            resolver,
            sessions: Sessions::default(),
            metrics: Metrics::default(),
            udp: UdpLimits {
                max_sessions: config.limits.udp_sessions_per_device as usize,
                idle: config.limits.udp_idle_timeout,
                dns_idle: config.limits.udp_dns_idle_timeout,
            },
            udp_per_device: Mutex::new(HashMap::new()),
        };
        Ok(Self {
            endpoint,
            state: Arc::new(state),
            pin,
        })
    }

    /// UDP address the server listens on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// SHA-256 of the certificate's SPKI, for connection URIs.
    pub fn pin(&self) -> [u8; 32] {
        self.pin
    }

    /// Shared state, for reloads and status.
    pub fn state(&self) -> Arc<State> {
        self.state.clone()
    }

    /// Endpoint handle; closing it stops [`Server::run`].
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Serves connections until the endpoint closes.
    pub async fn run(self) {
        while let Some(incoming) = self.endpoint.accept().await {
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming, state).await {
                    tracing::debug!(error = %e, "connection ended");
                }
            });
        }
    }
}

fn load_certificate(
    config: &Config,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ServerError> {
    let bad = |what: &str| ServerError::Config(what.to_owned());
    match config.tls.mode {
        TlsMode::Files => {
            let cert = config
                .tls
                .cert
                .as_ref()
                .ok_or_else(|| bad("tls.cert is required"))?;
            let key = config
                .tls
                .key
                .as_ref()
                .ok_or_else(|| bad("tls.key is required"))?;
            let chain = CertificateDer::pem_file_iter(cert)
                .and_then(|it| it.collect::<Result<Vec<_>, _>>())
                .map_err(|e| ServerError::Config(format!("{}: {e}", cert.display())))?;
            if chain.is_empty() {
                return Err(bad("tls.cert holds no certificate"));
            }
            let key = PrivateKeyDer::from_pem_file(key)
                .map_err(|e| ServerError::Config(format!("{}: {e}", key.display())))?;
            Ok((chain, key))
        }
        TlsMode::SelfSigned => {
            let name = config
                .server
                .domain
                .clone()
                .unwrap_or_else(|| "localhost".into());
            let key = rcgen::KeyPair::generate().map_err(|e| ServerError::Config(e.to_string()))?;
            let cert = rcgen::CertificateParams::new(vec![name])
                .and_then(|p| p.self_signed(&key))
                .map_err(|e| ServerError::Config(e.to_string()))?;
            let key = PrivateKeyDer::try_from(key.serialize_der()).map_err(bad)?;
            Ok((vec![cert.der().clone()], key))
        }
        TlsMode::Acme | TlsMode::AcmeIp => Err(bad("ACME modes are not available yet; use files")),
    }
}

/// Authenticates one QUIC connection and serves its streams.
async fn handle_connection(incoming: Incoming, state: Arc<State>) -> Result<(), String> {
    let conn = incoming.await.map_err(|e| e.to_string())?;
    state.metrics.connections.fetch_add(1, Ordering::Relaxed);
    // The client's HTTP/3 control stream and any other unidirectional streams: read and drop.
    let uni = conn.clone();
    tokio::spawn(async move {
        while let Ok(mut stream) = uni.accept_uni().await {
            tokio::spawn(
                async move { while let Ok(Some(_)) = stream.read_chunk(4096, true).await {} },
            );
        }
    });
    let authed = tokio::time::timeout(HANDSHAKE_TIMEOUT, authenticate(&conn, &state)).await;
    let Ok(Some((accepted, auth_send, auth_recv))) = authed else {
        // Like a web server after a 404: let the response reach the client and leave closing
        // to it, within the handshake timeout.
        let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.closed()).await;
        conn.close(0u32.into(), b"");
        return Err("not authenticated".into());
    };
    let sid = accepted.session.sid;
    let name = state
        .registry()
        .get(&accepted.device)
        .map(|d| d.name.clone())
        .unwrap_or_default();
    tracing::info!(device = %accepted.device, name = %name, sid = format_args!("{sid:x}"), "session started");
    let (control_tx, control_rx) = mpsc::channel(64);
    state.sessions.insert(
        sid,
        Session {
            device: accepted.device,
            name,
            platform: accepted.client.platform,
            client_version: accepted.client.client_version,
            transport: "quic",
            started: Instant::now(),
            control: control_tx.clone(),
            conn: conn.clone(),
        },
    );
    let transport = QuicTransport::new(conn);
    tokio::spawn(write_control(auth_send, control_rx));
    let nat = UdpNat::new(
        transport.clone(),
        state.clone(),
        control_tx.clone(),
        state.udp,
        state.udp_counter(accepted.device),
    );
    tokio::spawn(read_control(auth_recv, nat.clone(), control_tx));
    let datagrams = {
        let (transport, nat) = (transport.clone(), nat.clone());
        tokio::spawn(async move {
            while let Ok(datagram) = transport.recv_datagram().await {
                nat.handle(datagram).await;
            }
        })
    };
    while let Ok((send, recv)) = transport.accept_stream().await {
        let state = state.clone();
        let conn = transport.connection().clone();
        tokio::spawn(async move {
            let closed = async move {
                conn.closed().await;
            };
            proxy::handle_stream(send, recv, &state, closed).await;
        });
    }
    datagrams.abort();
    nat.shutdown();
    state.sessions.remove(sid);
    tracing::info!(sid = format_args!("{sid:x}"), "session ended");
    Ok(())
}

/// Writes control frames to the client, each in an HTTP/3 `DATA` frame on the auth stream.
async fn write_control(mut send: quinn::SendStream, mut frames: mpsc::Receiver<ControlFrame>) {
    while let Some(frame) = frames.recv().await {
        let mut body = Vec::new();
        if frame.encode(&mut body).is_err() {
            continue;
        }
        if send.write_all(&encode_data_frame(&body)).await.is_err() {
            return;
        }
    }
}

/// Serves the client's control frames: answers `Ping`, closes UDP sessions on `UdpClose`.
async fn read_control(
    mut recv: quinn::RecvStream,
    nat: Arc<UdpNat>,
    reply: mpsc::Sender<ControlFrame>,
) {
    let (mut data, mut frames) = (DataFrameReader::default(), ControlReader::default());
    let mut buf = vec![0u8; 4096];
    while let Ok(Some(n)) = recv.read(&mut buf).await {
        let Ok(bytes) = data.push(&buf[..n]) else {
            return;
        };
        let Ok(parsed) = frames.push(&bytes) else {
            return;
        };
        for frame in parsed {
            match frame {
                ControlFrame::Ping { nonce } => {
                    let _ = reply.try_send(ControlFrame::Pong { nonce });
                }
                ControlFrame::UdpClose { session_id, .. } => {
                    nat.close(session_id);
                }
                _ => {}
            }
        }
    }
}

/// Reads the auth request from the first bidi stream; answers success or `404`.
async fn authenticate(
    conn: &quinn::Connection,
    state: &State,
) -> Option<(auth::Accepted, quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = conn.accept_bi().await.ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let request = loop {
        match AuthRequest::decode(AuthTransport::Quic, &buf) {
            Ok(Some((request, _))) => break Ok(request),
            Ok(None) => {}
            Err(failure) => break Err(failure),
        }
        let n = recv.read(&mut chunk).await.ok()??;
        buf.extend_from_slice(&chunk[..n]);
    };
    let mut sid = [0u8; 8];
    getrandom::fill(&mut sid).ok()?;
    let registry = state.registry();
    let result = request
        .and_then(|r| auth::authenticate(&r, &*registry, &state.policy, u64::from_be_bytes(sid)));
    match result {
        Ok(accepted) => {
            let response = auth::accept_response(AuthTransport::Quic, &accepted.session);
            send.write_all(&response).await.ok()?;
            Some((accepted, send, recv))
        }
        Err(failure) => {
            tracing::info!(reason = %failure, remote = %conn.remote_address(), "auth rejected");
            let _ = send
                .write_all(&auth::not_found_response(AuthTransport::Quic))
                .await;
            let _ = send.finish();
            None
        }
    }
}

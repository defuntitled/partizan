//! UDP NAT for one session: a socket per UDP session, endpoint-independent mapping and
//! filtering (full cone), so P2P calls through ICE go direct instead of via TURN.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use proto::control::udp_close;
use proto::{ControlFrame, Host, TargetAddr, UdpDatagram};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio::time::Instant;
use transport::{DatagramError, Transport};

use crate::State;
use crate::dial::resolve;

/// UDP NAT settings.
#[derive(Debug, Clone, Copy)]
pub struct UdpLimits {
    /// UDP sessions at once.
    pub max_sessions: usize,
    /// Idle timeout.
    pub idle: Duration,
    /// Idle timeout when the first destination is port 53.
    pub dns_idle: Duration,
}

struct Entry {
    socket: Arc<UdpSocket>,
    /// Last destination as sent by the client, and where it resolved to.
    last: Option<(TargetAddr, SocketAddr)>,
    activity: Arc<AtomicU64>,
    task: AbortHandle,
}

/// The NAT for one session.
pub struct UdpNat {
    transport: Arc<dyn Transport>,
    state: Arc<State>,
    control: mpsc::Sender<ControlFrame>,
    limits: UdpLimits,
    /// UDP sessions of this device across all its connections.
    device_count: Arc<AtomicUsize>,
    started: Instant,
    sessions: Mutex<HashMap<u64, Entry>>,
}

impl UdpNat {
    /// NAT that answers through `transport` and reports closes on `control`; the session
    /// limit is shared through `device_count` by all connections of the device.
    pub fn new(
        transport: Arc<dyn Transport>,
        state: Arc<State>,
        control: mpsc::Sender<ControlFrame>,
        limits: UdpLimits,
        device_count: Arc<AtomicUsize>,
    ) -> Arc<Self> {
        Arc::new(Self {
            transport,
            state,
            control,
            limits,
            device_count,
            started: Instant::now(),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Entry>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Live UDP sessions.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True if there are none.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Handles one datagram from the client.
    pub async fn handle(self: &Arc<Self>, raw: Bytes) {
        let Ok(datagram) = UdpDatagram::decode(raw) else {
            self.state
                .metrics
                .udp_malformed_drops
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let id = datagram.session_id;
        let existing = self
            .lock()
            .get(&id)
            .map(|e| (e.socket.clone(), e.last.clone(), e.activity.clone()));
        let (socket, activity, dst) = match (existing, datagram.addr) {
            // A new session must name its destination.
            (None, None) => {
                self.state
                    .metrics
                    .udp_malformed_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            (None, Some(target)) => {
                let Some(dst) = self.destination(&target).await else {
                    self.notify_close(id, udp_close::NOT_ALLOWED);
                    return;
                };
                match self.open(id, target, dst) {
                    Some((socket, activity)) => (socket, activity, dst),
                    None => return,
                }
            }
            (Some((socket, Some((_, dst)), activity)), None) => (socket, activity, dst),
            (Some((socket, last, activity)), Some(target)) => {
                let dst = match last {
                    Some((prev, dst)) if prev == target => dst,
                    _ => match self.destination(&target).await {
                        Some(dst) => {
                            if let Some(e) = self.lock().get_mut(&id) {
                                e.last = Some((target, dst));
                            }
                            dst
                        }
                        None => {
                            self.state
                                .metrics
                                .udp_denied_drops
                                .fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    },
                };
                (socket, activity, dst)
            }
            (Some((_, None, _)), None) => return,
        };
        activity.store(self.now_ms(), Ordering::Relaxed);
        let _ = socket
            .send_to(&datagram.payload, to_socket_family(&socket, dst))
            .await;
    }

    /// Resolves and checks a destination; `None` if unresolvable or not allowed.
    async fn destination(&self, target: &TargetAddr) -> Option<SocketAddr> {
        // The benchmark echo lives on loopback, which the egress policy rightly refuses.
        if let Some(echo) = self.state.bench_udp
            && crate::bench::is_bench(target)
        {
            return (target.port == proto::bench::ECHO).then_some(echo);
        }
        let ips = resolve(&target.host, &self.state.resolver).await.ok()?;
        let ip = ips.into_iter().find(|ip| self.state.egress.allows(*ip))?;
        Some(SocketAddr::new(ip, target.port))
    }

    /// Creates a UDP session; `None` (and a `UdpClose`) over the limit.
    fn open(
        self: &Arc<Self>,
        id: u64,
        target: TargetAddr,
        dst: SocketAddr,
    ) -> Option<(Arc<UdpSocket>, Arc<AtomicU64>)> {
        let mut sessions = self.lock();
        let reserved = self
            .device_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.limits.max_sessions).then_some(n + 1)
            })
            .is_ok();
        if !reserved {
            drop(sessions);
            self.notify_close(id, udp_close::LIMIT);
            return None;
        }
        let socket = match bind_dual_stack() {
            Ok(socket) => Arc::new(socket),
            Err(e) => {
                self.device_count.fetch_sub(1, Ordering::AcqRel);
                tracing::warn!(error = %e, "UDP socket");
                return None;
            }
        };
        let idle = if target.port == 53 {
            self.limits.dns_idle
        } else {
            self.limits.idle
        };
        let activity = Arc::new(AtomicU64::new(self.now_ms()));
        let task = tokio::spawn(
            self.clone()
                .pump(id, socket.clone(), activity.clone(), idle),
        )
        .abort_handle();
        sessions.insert(
            id,
            Entry {
                socket: socket.clone(),
                last: Some((target, dst)),
                activity: activity.clone(),
                task,
            },
        );
        Some((socket, activity))
    }

    /// Forwards everything the socket receives, from any source, until idle.
    async fn pump(
        self: Arc<Self>,
        id: u64,
        socket: Arc<UdpSocket>,
        activity: Arc<AtomicU64>,
        idle: Duration,
    ) {
        let mut buf = vec![0u8; 65_535];
        loop {
            let last = activity.load(Ordering::Relaxed);
            let deadline = self.started + Duration::from_millis(last) + idle;
            tokio::select! {
                received = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = received else { continue };
                    activity.store(self.now_ms(), Ordering::Relaxed);
                    let reply = UdpDatagram {
                        session_id: id,
                        addr: Some(target_addr(from)),
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    let mut out = Vec::with_capacity(n + 32);
                    if reply.encode(&mut out).is_err() {
                        continue;
                    }
                    if let Err(DatagramError::TooLarge) = self.transport.send_datagram(out.into()) {
                        self.state.metrics.udp_oversize_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    if activity.load(Ordering::Relaxed) == last {
                        if self.lock().remove(&id).is_some() {
                            self.device_count.fetch_sub(1, Ordering::AcqRel);
                        }
                        self.notify_close(id, udp_close::IDLE);
                        return;
                    }
                }
            }
        }
    }

    /// Closes a UDP session the client asked to close; returns whether it existed.
    pub fn close(&self, id: u64) -> bool {
        match self.lock().remove(&id) {
            Some(entry) => {
                entry.task.abort();
                self.device_count.fetch_sub(1, Ordering::AcqRel);
                true
            }
            None => false,
        }
    }

    /// Stops every UDP session; call when the connection ends.
    pub fn shutdown(&self) {
        for (_, entry) in self.lock().drain() {
            entry.task.abort();
            self.device_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn notify_close(&self, id: u64, reason: u8) {
        let _ = self.control.try_send(ControlFrame::UdpClose {
            session_id: id,
            reason,
        });
    }
}

/// `[::]:0` accepting IPv4 too, or `0.0.0.0:0` on hosts without IPv6.
fn bind_dual_stack() -> std::io::Result<UdpSocket> {
    let v6 = (|| {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
        Ok::<_, std::io::Error>(socket)
    })();
    let socket = match v6 {
        Ok(socket) => socket,
        Err(_) => {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
            socket
        }
    };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// IPv4 destinations as mapped addresses on a dual-stack socket.
fn to_socket_family(socket: &UdpSocket, dst: SocketAddr) -> SocketAddr {
    match (socket.local_addr(), dst) {
        (Ok(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => dst,
    }
}

/// Source address for `HAS_ADDR`, IPv4-mapped shown as IPv4.
fn target_addr(from: SocketAddr) -> TargetAddr {
    let host = match from.ip() {
        IpAddr::V4(v4) => Host::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => Host::V4(v4),
            None => Host::V6(v6),
        },
    };
    TargetAddr {
        host,
        port: from.port(),
    }
}

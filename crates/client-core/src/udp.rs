//! UDP flows: one per source of the traffic source, each a UDP session on the server.
//!
//! Flows outlive sessions: after a reconnect, or after the server closed the UDP session, the
//! next datagram carries the destination again and the server opens a fresh one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use proto::control::udp_close;
use proto::{ControlFrame, TargetAddr, UdpDatagram};
use tokio::sync::mpsc;
use transport::{DatagramError, Transport};

use crate::session::{Engine, EngineError};

/// Replies buffered per flow before new ones are dropped.
const REPLY_QUEUE: usize = 256;

/// A datagram from the far side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpReply {
    /// Who sent it.
    pub src: TargetAddr,
    /// Payload.
    pub payload: Bytes,
}

/// Why a datagram was not sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UdpSendError {
    /// No session.
    #[error(transparent)]
    Session(#[from] EngineError),
    /// Larger than the transport takes; dropped, no fragmentation in v1.
    #[error("datagram too large")]
    TooLarge,
    /// The session cannot carry datagrams.
    #[error("datagrams unavailable: {0}")]
    Unavailable(DatagramError),
}

struct FlowShared {
    replies: mpsc::Sender<UdpReply>,
    /// The next datagram must carry the destination.
    needs_addr: AtomicBool,
}

/// Engine-wide table of flows.
#[derive(Default)]
pub(crate) struct UdpRegistry {
    next_id: AtomicU64,
    flows: Mutex<HashMap<u64, Arc<FlowShared>>>,
    /// Datagrams dropped: oversize on send, or a full reply queue.
    pub(crate) drops: AtomicU64,
}

impl UdpRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<FlowShared>>> {
        self.flows.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn register(&self) -> (u64, Arc<FlowShared>, mpsc::Receiver<UdpReply>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel(REPLY_QUEUE);
        let shared = Arc::new(FlowShared {
            replies: tx,
            needs_addr: AtomicBool::new(true),
        });
        self.lock().insert(id, shared.clone());
        (id, shared, rx)
    }

    /// Routes a datagram from the server to its flow.
    pub(crate) fn deliver(&self, datagram: UdpDatagram) {
        let Some(flow) = self.lock().get(&datagram.session_id).cloned() else {
            return;
        };
        // The server always names the source in v1; a reply without it is useless.
        let Some(src) = datagram.addr else { return };
        let reply = UdpReply {
            src,
            payload: datagram.payload,
        };
        if flow.replies.try_send(reply).is_err() {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The server closed this UDP session; the flow reopens it with its next datagram.
    pub(crate) fn server_closed(&self, id: u64) {
        if let Some(flow) = self.lock().get(&id) {
            flow.needs_addr.store(true, Ordering::Relaxed);
        }
    }

    /// A new connection: every flow must name its destination again.
    pub(crate) fn reset_all(&self) {
        for flow in self.lock().values() {
            flow.needs_addr.store(true, Ordering::Relaxed);
        }
    }

    /// Number of open flows.
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
}

/// One UDP flow; dropping it closes the server-side UDP session.
pub struct UdpFlow {
    engine: Engine,
    id: u64,
    shared: Arc<FlowShared>,
    replies: mpsc::Receiver<UdpReply>,
    last_dst: Option<TargetAddr>,
}

impl Engine {
    /// Opens a UDP flow; nothing goes to the server until the first datagram.
    pub fn open_udp(&self) -> UdpFlow {
        let (id, shared, replies) = self.inner.udp.register();
        UdpFlow {
            engine: self.clone(),
            id,
            shared,
            replies,
            last_dst: None,
        }
    }

    /// Open UDP flows.
    pub fn udp_flows(&self) -> usize {
        self.inner.udp.len()
    }
}

impl UdpFlow {
    /// UDP session id on the wire.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Sends a datagram to `dst`; the address goes on the wire only when it changes.
    pub async fn send(&mut self, dst: TargetAddr, payload: Bytes) -> Result<(), UdpSendError> {
        let session = self.engine.session().await?;
        let fresh = self.shared.needs_addr.swap(false, Ordering::Relaxed);
        let with_addr = fresh || self.last_dst.as_ref() != Some(&dst);
        let datagram = UdpDatagram {
            session_id: self.id,
            addr: with_addr.then(|| dst.clone()),
            payload,
        };
        let mut out = Vec::with_capacity(datagram.payload.len() + 32);
        if datagram.encode(&mut out).is_err() {
            return Err(UdpSendError::TooLarge);
        }
        match session.transport.send_datagram(out.into()) {
            Ok(()) => {
                self.last_dst = Some(dst);
                Ok(())
            }
            Err(e) => {
                // Not sent: the address must go out with the next try.
                if with_addr {
                    self.shared.needs_addr.store(true, Ordering::Relaxed);
                }
                self.engine.inner.udp.drops.fetch_add(1, Ordering::Relaxed);
                Err(match e {
                    DatagramError::TooLarge => UdpSendError::TooLarge,
                    other => UdpSendError::Unavailable(other),
                })
            }
        }
    }

    /// Next reply; `None` once the flow is closed.
    pub async fn recv(&mut self) -> Option<UdpReply> {
        self.replies.recv().await
    }
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.engine.inner.udp.lock().remove(&self.id);
        // Best effort: tell the live session; an idle timeout covers a missed close.
        let current = self.engine.inner.current.borrow().clone();
        if let Some(session) = current.filter(|s| s.is_alive()) {
            let _ = session.control.try_send(ControlFrame::UdpClose {
                session_id: self.id,
                reason: udp_close::NORMAL,
            });
        }
    }
}

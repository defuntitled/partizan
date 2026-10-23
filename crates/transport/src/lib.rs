//! Transports behind one interface: QUIC on quinn and, later, TCP+TLS with the `proto` mux.
//!
//! Streams carry proxied TCP connections, datagrams carry UDP. Datagram sends never block:
//! under pressure they are dropped.

#[cfg(feature = "chrome")]
pub mod chrome;
mod config;
pub mod quic;
pub mod tcp;
pub mod tls;

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use proto::ErrorCode;
use tokio::io::{AsyncRead, AsyncWrite};

pub use config::{Congestion, QuicConfig, parse_duration};

/// Sending half of a stream.
pub trait SendStream: AsyncWrite + Send + Unpin {
    /// Abandons the stream with an error code (QUIC `RESET_STREAM`, mux `RST`).
    fn reset(&mut self, code: ErrorCode);
}

/// Receiving half of a stream.
pub trait RecvStream: AsyncRead + Send + Unpin {
    /// Tells the peer to stop sending (QUIC `STOP_SENDING`).
    fn stop(&mut self, code: ErrorCode);
}

/// Boxed sending half.
pub type SendHalf = Box<dyn SendStream>;
/// Boxed receiving half.
pub type RecvHalf = Box<dyn RecvStream>;

/// Code the peer reset a stream with, from a read or write error on a [`RecvHalf`] /
/// [`SendHalf`]; `None` for other errors.
pub fn reset_code(e: &std::io::Error) -> Option<ErrorCode> {
    if let Some(reset) = e
        .get_ref()
        .and_then(|e| e.downcast_ref::<tcp::StreamReset>())
    {
        return Some(reset.0);
    }
    quic::reset_code(e)
}

/// Connection-level failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// Closed by the peer with an application error code (e.g. `REVOKED`).
    #[error("closed by peer with code {0:?}")]
    ClosedByPeer(ErrorCode),
    /// Closed locally.
    #[error("closed locally")]
    ClosedLocally,
    /// Timed out or lost for a transport reason.
    #[error("connection lost: {0}")]
    Lost(String),
}

/// Datagram send failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramError {
    /// Larger than [`Transport::max_datagram_size`].
    #[error("datagram too large")]
    TooLarge,
    /// Peer does not accept datagrams.
    #[error("datagrams not supported by the peer")]
    Unsupported,
    /// Connection is gone.
    #[error("connection closed")]
    Closed,
}

/// Counters for `status` and metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats {
    /// Smoothed round-trip time.
    pub rtt: Duration,
    /// Bytes sent on the wire.
    pub bytes_sent: u64,
    /// Bytes received on the wire.
    pub bytes_received: u64,
    /// Path MTU currently in use.
    pub mtu: u16,
}

/// An established, authenticated connection to the peer.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Opens a stream for one proxied TCP connection.
    async fn open_stream(&self) -> Result<(SendHalf, RecvHalf), TransportError>;
    /// Waits for the peer to open a stream.
    async fn accept_stream(&self) -> Result<(SendHalf, RecvHalf), TransportError>;
    /// Queues a datagram; never blocks, drops under pressure.
    fn send_datagram(&self, data: Bytes) -> Result<(), DatagramError>;
    /// Waits for the next datagram.
    async fn recv_datagram(&self) -> Result<Bytes, TransportError>;
    /// Largest datagram the path takes now, `None` if datagrams are unavailable.
    fn max_datagram_size(&self) -> Option<usize>;
    /// Current counters.
    fn stats(&self) -> TransportStats;
    /// Closes the connection with an application error code.
    fn close(&self, code: ErrorCode, reason: &[u8]);
    /// Resolves when the connection is gone, with the reason.
    async fn closed(&self) -> TransportError;
}

/// The session's control channel: HTTP/3 `DATA` frames on the auth stream (QUIC) or mux
/// `CONTROL` frames (TCP+TLS).
#[async_trait]
pub trait ControlChannel: Send + Sync {
    /// Sends one encoded control frame.
    async fn send(&self, frame: Vec<u8>) -> Result<(), TransportError>;
    /// Next chunk of control-channel bytes; `None` once the channel is closed.
    async fn recv(&self) -> Option<Vec<u8>>;
}

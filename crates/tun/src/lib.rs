//! Traffic source: IP packets from a TUN fd, feeding `client-core`.
//!
//! The counterpart of `socks5` for platforms where the system hands over a TUN interface
//! (Android `VpnService`, later desktop). TCP goes through a userspace `smoltcp` stack and
//! comes out as [`TcpRequest`]s; UDP is parsed directly, one flow per source. Nothing listens
//! on a local socket. [`Split`] rules send each connection and datagram either through the
//! tunnel or [`Direct`]ly. Destinations are always IP addresses: names were resolved by the
//! system before the packet reached the interface.
//!
//! `unsafe` is denied except for registering the fd with the reactor in `device`.

#![deny(unsafe_code)]

mod device;
mod diagnostics;
mod direct;
mod engine;
mod packet;
mod split;
mod stack;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
pub use client_core::TcpRequest;
use tokio::sync::mpsc;

pub use device::{FdDevice, PacketDevice};
pub use diagnostics::{Diagnostics, StackMetrics};
pub use direct::{Direct, Protect};
pub use split::{IpNet, ParseNetError, Path, Split, SplitConfig, SplitMode, SplitStats};
pub use stack::run;

/// Where the stack hands what it takes off the interface: [`client_core::Engine`] for the
/// tunnel, [`Direct`] for the rest.
pub trait Handler: Send + Sync + 'static {
    /// A new TCP connection. Called on the stack task: must not block.
    fn tcp(&self, request: TcpRequest);

    /// A new UDP flow from `source`. Outgoing datagrams arrive on `datagrams`, replies go to
    /// `replies` (their `dst` is `source`). The flow ends when `datagrams` closes. Called on the
    /// stack task: must not block.
    fn udp(
        &self,
        source: SocketAddr,
        datagrams: mpsc::Receiver<UdpPacket>,
        replies: mpsc::Sender<UdpPacket>,
    );
}

/// A UDP datagram crossing the interface, in either direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    /// Sender.
    pub src: SocketAddr,
    /// Receiver.
    pub dst: SocketAddr,
    /// Payload.
    pub payload: Bytes,
}

/// Stack settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// MTU of the interface: no packet written to it is larger.
    pub mtu: usize,
    /// TCP connections open at once; further SYNs are refused with RST.
    pub max_tcp: usize,
    /// UDP sources tracked at once; datagrams from further sources are dropped.
    pub max_udp: usize,
    /// Per-connection `smoltcp` receive and send buffer, bytes each.
    pub tcp_buffer: usize,
    /// A UDP flow with no traffic either way for this long is closed.
    pub udp_idle: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Fits a QUIC DATAGRAM without fragmentation; WebRTC media (~1200 B) passes whole.
            mtu: 1400,
            max_tcp: 1024,
            max_udp: 512,
            tcp_buffer: 32 * 1024,
            udp_idle: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unsafe_is_denied() {
        let mut header = include_str!("lib.rs")
            .lines()
            .map(str::trim)
            .take_while(|l| l.is_empty() || l.starts_with("//!") || l.starts_with("#!["));
        assert!(header.any(|l| l == "#![deny(unsafe_code)]"));
    }
}

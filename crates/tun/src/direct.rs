//! The direct path: traffic that bypasses the tunnel leaves through the device's own sockets.
//!
//! Those sockets must not be routed back into the interface. On Android the app is excluded
//! from its own VPN, or each socket is passed to `VpnService.protect()` through [`Protect`].

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use bytes::Bytes;
use client_core::TcpRequest;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::mpsc;

use crate::engine::socket_addr;
use crate::{Handler, UdpPacket};

/// Called with every socket before it sends anything; `false` refuses the socket.
pub type Protect = Arc<dyn Fn(RawFd) -> bool + Send + Sync>;

/// Largest UDP payload taken from the network.
const MAX_DATAGRAM: usize = 65_535;

/// Handler that connects to destinations itself, outside the tunnel.
#[derive(Clone, Default)]
pub struct Direct {
    protect: Option<Protect>,
}

impl Direct {
    /// Every socket goes through `protect` first.
    pub fn with_protect(protect: Protect) -> Self {
        Self {
            protect: Some(protect),
        }
    }

    fn protect(&self, fd: RawFd) -> io::Result<()> {
        match &self.protect {
            Some(protect) if !protect(fd) => Err(io::Error::other("socket protection refused")),
            _ => Ok(()),
        }
    }

    async fn connect(&self, dst: SocketAddr) -> io::Result<tokio::net::TcpStream> {
        let socket = match dst {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        self.protect(socket.as_raw_fd())?;
        let stream = socket.connect(dst).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    fn bind(&self, source: SocketAddr) -> io::Result<UdpSocket> {
        let any: SocketAddr = match source {
            SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = std::net::UdpSocket::bind(any)?;
        self.protect(socket.as_raw_fd())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }
}

impl Handler for Direct {
    fn tcp(&self, request: TcpRequest) {
        let this = self.clone();
        tokio::spawn(async move {
            let Some(dst) = socket_addr(&request.dst) else {
                return;
            };
            let mut io = request.io;
            match this.connect(dst).await {
                Ok(mut stream) => {
                    if let Err(e) = tokio::io::copy_bidirectional(&mut io, &mut stream).await {
                        log::debug!("direct TCP to {dst}: {e}");
                    }
                }
                // Dropping `io` closes the app's connection.
                Err(e) => log::debug!("direct TCP to {dst}: {e}"),
            }
        });
    }

    fn udp(
        &self,
        source: SocketAddr,
        mut datagrams: mpsc::Receiver<UdpPacket>,
        replies: mpsc::Sender<UdpPacket>,
    ) {
        let socket = match self.bind(source) {
            Ok(socket) => socket,
            Err(e) => {
                // Dropping `datagrams` ends the flow; the stack opens a new one next time.
                log::debug!("direct UDP for {source}: {e}");
                return;
            }
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                tokio::select! {
                    outgoing = datagrams.recv() => match outgoing {
                        Some(packet) => {
                            if let Err(e) = socket.send_to(&packet.payload, packet.dst).await {
                                log::debug!("direct UDP to {}: {e}", packet.dst);
                            }
                        }
                        None => return,
                    },
                    incoming = socket.recv_from(&mut buf) => match incoming {
                        Ok((n, src)) => {
                            let reply = UdpPacket {
                                src,
                                dst: source,
                                payload: Bytes::copy_from_slice(&buf[..n]),
                            };
                            let _ = replies.try_send(reply);
                        }
                        Err(e) => log::debug!("direct UDP for {source}: {e}"),
                    },
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use proto::{Host, TargetAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn counting() -> (Direct, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let direct = Direct::with_protect(Arc::new(move |fd| {
            assert!(fd >= 0);
            seen.fetch_add(1, Ordering::Relaxed);
            true
        }));
        (direct, calls)
    }

    #[tokio::test]
    async fn tcp_connects_through_a_protected_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let (direct, calls) = counting();
        let (mut app, io) = tokio::io::duplex(1024);
        let dst = TargetAddr {
            host: Host::V4(std::net::Ipv4Addr::LOCALHOST),
            port: addr.port(),
        };
        direct.tcp(TcpRequest {
            dst,
            io: Box::new(io),
        });
        app.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refused_protection_closes_the_connection() {
        let direct = Direct::with_protect(Arc::new(|_| false));
        let (mut app, io) = tokio::io::duplex(1024);
        direct.tcp(TcpRequest {
            dst: TargetAddr {
                host: Host::V4(std::net::Ipv4Addr::LOCALHOST),
                port: 9,
            },
            io: Box::new(io),
        });
        let mut buf = [0u8; 1];
        assert_eq!(app.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn udp_flow_sends_and_relays_replies() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&buf[..n], from).await.unwrap();
        });
        let (direct, calls) = counting();
        let source: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let (tx, rx) = mpsc::channel(4);
        let (replies_tx, mut replies) = mpsc::channel(4);
        direct.udp(source, rx, replies_tx);
        tx.send(UdpPacket {
            src: source,
            dst: server_addr,
            payload: Bytes::from_static(b"hello"),
        })
        .await
        .unwrap();
        let reply = replies.recv().await.unwrap();
        assert_eq!(
            reply,
            UdpPacket {
                src: server_addr,
                dst: source,
                payload: Bytes::from_static(b"hello")
            }
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

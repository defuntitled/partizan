//! `client-core`'s engine as the stack's handler.

use std::net::SocketAddr;

use client_core::{Engine, TcpRequest, UdpReply};
use proto::{Host, TargetAddr};
use tokio::sync::mpsc;

use crate::{Handler, UdpPacket};

impl Handler for Engine {
    fn tcp(&self, request: TcpRequest) {
        let engine = self.clone();
        tokio::spawn(async move { engine.handle_tcp(request).await });
    }

    fn udp(
        &self,
        source: SocketAddr,
        mut datagrams: mpsc::Receiver<UdpPacket>,
        replies: mpsc::Sender<UdpPacket>,
    ) {
        let mut flow = self.open_udp();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    outgoing = datagrams.recv() => match outgoing {
                        Some(packet) => {
                            if let Err(e) = flow.send(target(packet.dst), packet.payload).await {
                                log::debug!("UDP flow {}: {e}", flow.id());
                            }
                        }
                        None => return,
                    },
                    incoming = flow.recv() => match incoming {
                        Some(UdpReply { src, payload }) => {
                            // The server names sources by IP; a name cannot go into a packet.
                            let Some(src) = socket_addr(&src) else { continue };
                            let _ = replies.try_send(UdpPacket { src, dst: source, payload });
                        }
                        None => return,
                    },
                }
            }
        });
    }
}

pub(crate) fn target(addr: SocketAddr) -> TargetAddr {
    let host = match addr {
        SocketAddr::V4(a) => Host::V4(*a.ip()),
        SocketAddr::V6(a) => Host::V6(*a.ip()),
    };
    TargetAddr {
        host,
        port: addr.port(),
    }
}

pub(crate) fn socket_addr(addr: &TargetAddr) -> Option<SocketAddr> {
    let ip = match &addr.host {
        Host::V4(ip) => (*ip).into(),
        Host::V6(ip) => (*ip).into(),
        Host::Domain(_) => return None,
    };
    Some(SocketAddr::new(ip, addr.port))
}

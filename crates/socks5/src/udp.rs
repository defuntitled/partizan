//! `UDP ASSOCIATE` (RFC 1928 §7): a relay socket per association, a UDP flow per source.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use client_core::{Engine, UdpReply};
use proto::{Host, TargetAddr};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::{Error, reply, write_reply_bound};

/// Sources per association; each is a UDP session on the server.
const MAX_FLOWS: usize = 512;
/// Outgoing datagrams queued per flow before new ones are dropped.
const FLOW_QUEUE: usize = 256;

/// Serves one association until its TCP control connection closes.
pub(crate) async fn associate(mut tcp: TcpStream, engine: &Engine) -> Result<(), Error> {
    let client_ip = tcp.peer_addr()?.ip();
    let socket = Arc::new(UdpSocket::bind((tcp.local_addr()?.ip(), 0)).await?);
    write_reply_bound(&mut tcp, reply::SUCCEEDED, socket.local_addr()?).await?;
    let mut flows: HashMap<SocketAddr, mpsc::Sender<(TargetAddr, Bytes)>> = HashMap::new();
    let mut buf = vec![0u8; 65_535];
    let mut control = [0u8; 64];
    loop {
        tokio::select! {
            // The association lives as long as the TCP connection.
            read = tcp.read(&mut control) => {
                if matches!(read, Ok(0) | Err(_)) {
                    break;
                }
            }
            received = socket.recv_from(&mut buf) => {
                let Ok((n, from)) = received else { continue };
                // Only the client that asked for the association may use it.
                if from.ip() != client_ip {
                    continue;
                }
                let Some((dst, header)) = parse_header(&buf[..n]) else { continue };
                let payload = Bytes::copy_from_slice(&buf[header..n]);
                flows.retain(|_, tx| !tx.is_closed());
                let tx = match flows.get(&from) {
                    Some(tx) => tx.clone(),
                    None if flows.len() < MAX_FLOWS => {
                        let tx = spawn_flow(engine, socket.clone(), from);
                        flows.insert(from, tx.clone());
                        tx
                    }
                    None => continue,
                };
                let _ = tx.try_send((dst, payload));
            }
        }
    }
    // Dropping the senders ends the flow tasks; each flow closes its server UDP session.
    Ok(())
}

/// Task owning one flow: client datagrams out, replies back to `source`.
fn spawn_flow(
    engine: &Engine,
    socket: Arc<UdpSocket>,
    source: SocketAddr,
) -> mpsc::Sender<(TargetAddr, Bytes)> {
    let (tx, mut rx) = mpsc::channel::<(TargetAddr, Bytes)>(FLOW_QUEUE);
    let mut flow = engine.open_udp();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                outgoing = rx.recv() => match outgoing {
                    Some((dst, payload)) => {
                        if let Err(e) = flow.send(dst, payload).await {
                            log::debug!("UDP flow {}: {e}", flow.id());
                        }
                    }
                    None => return,
                },
                incoming = flow.recv() => match incoming {
                    Some(UdpReply { src, payload }) => {
                        let mut packet = encode_header(&src);
                        packet.extend_from_slice(&payload);
                        let _ = socket.send_to(&packet, source).await;
                    }
                    None => return,
                },
            }
        }
    });
    tx
}

/// `RSV RSV FRAG ATYP DST.ADDR DST.PORT`; `None` for fragments (`FRAG ≠ 0`) and bad headers.
pub(crate) fn parse_header(buf: &[u8]) -> Option<(TargetAddr, usize)> {
    let (&[0, 0, frag, atyp], rest) = buf.split_first_chunk::<4>()? else {
        return None;
    };
    if frag != 0 {
        return None;
    }
    let (host, len) = match atyp {
        0x01 => (Host::V4(Ipv4Addr::from(*rest.first_chunk::<4>()?)), 4),
        0x04 => (Host::V6(Ipv6Addr::from(*rest.first_chunk::<16>()?)), 16),
        0x03 => {
            let n = usize::from(*rest.first()?);
            let name = std::str::from_utf8(rest.get(1..1 + n)?).ok()?;
            if name.is_empty() {
                return None;
            }
            (Host::Domain(name.to_owned()), 1 + n)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(*rest.get(len..)?.first_chunk::<2>()?);
    Some((TargetAddr { host, port }, 4 + len + 2))
}

/// Header for a reply from `src`.
pub(crate) fn encode_header(src: &TargetAddr) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    match &src.host {
        Host::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        Host::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            None => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
            }
        },
        Host::Domain(name) => {
            out.push(0x03);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&src.port.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_roundtrip_and_fragments_are_dropped() {
        let targets = [
            TargetAddr {
                host: Host::V4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 53,
            },
            TargetAddr {
                host: Host::V6(Ipv6Addr::LOCALHOST),
                port: 3478,
            },
            TargetAddr {
                host: Host::Domain("stun.example.org".into()),
                port: 3478,
            },
        ];
        for t in targets {
            let mut packet = encode_header(&t);
            let len = packet.len();
            packet.extend_from_slice(b"payload");
            assert_eq!(parse_header(&packet), Some((t, len)));
        }
        let mut fragment = encode_header(&TargetAddr {
            host: Host::V4(Ipv4Addr::LOCALHOST),
            port: 9,
        });
        fragment[2] = 1;
        assert_eq!(parse_header(&fragment), None, "FRAG != 0 is dropped");
        assert_eq!(parse_header(&[0, 0, 0, 0x01, 1, 2]), None, "truncated");
        assert_eq!(
            parse_header(&[0, 1, 0, 0x01, 1, 2, 3, 4, 0, 9]),
            None,
            "RSV must be zero"
        );
    }
}

//! Classifying packets read from the interface and building UDP packets written to it.

use std::net::{IpAddr, SocketAddr};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket,
    UdpRepr,
};

const UDP_HEADER: usize = 8;
const HOP_LIMIT: u8 = 64;

/// What a packet from the interface carries.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Inbound<'a> {
    /// A TCP segment; `ip` is the whole IP packet without trailing padding, for `smoltcp`.
    Tcp {
        src: SocketAddr,
        dst: SocketAddr,
        /// Opens a connection: SYN without ACK.
        syn: bool,
        ip: &'a [u8],
    },
    /// A UDP datagram.
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: &'a [u8],
    },
}

/// Why a packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reject {
    /// Truncated or inconsistent headers.
    Malformed,
    /// An IPv4 fragment; not reassembled.
    Fragment,
    /// Neither TCP nor UDP (ICMP, IPv6 extension headers, ...).
    Unsupported,
}

impl From<smoltcp::wire::Error> for Reject {
    fn from(_: smoltcp::wire::Error) -> Self {
        Self::Malformed
    }
}

/// Classifies one IP packet. Never panics, whatever the bytes.
pub(crate) fn parse(buf: &[u8]) -> Result<Inbound<'_>, Reject> {
    let version = buf.first().ok_or(Reject::Malformed)? >> 4;
    let (src, dst, protocol, payload, ip) = match version {
        4 => {
            let packet = Ipv4Packet::new_checked(buf)?;
            if packet.more_frags() || packet.frag_offset() != 0 {
                return Err(Reject::Fragment);
            }
            let len = usize::from(packet.total_len());
            (
                IpAddr::V4(packet.src_addr()),
                IpAddr::V4(packet.dst_addr()),
                packet.next_header(),
                packet.payload(),
                &buf[..len],
            )
        }
        6 => {
            let packet = Ipv6Packet::new_checked(buf)?;
            (
                IpAddr::V6(packet.src_addr()),
                IpAddr::V6(packet.dst_addr()),
                packet.next_header(),
                packet.payload(),
                &buf[..packet.total_len()],
            )
        }
        _ => return Err(Reject::Malformed),
    };
    match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload)?;
            Ok(Inbound::Tcp {
                src: SocketAddr::new(src, tcp.src_port()),
                dst: SocketAddr::new(dst, tcp.dst_port()),
                syn: tcp.syn() && !tcp.ack(),
                ip,
            })
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload)?;
            if udp.src_port() == 0 || udp.dst_port() == 0 {
                return Err(Reject::Malformed);
            }
            Ok(Inbound::Udp {
                src: SocketAddr::new(src, udp.src_port()),
                dst: SocketAddr::new(dst, udp.dst_port()),
                payload: udp.payload(),
            })
        }
        _ => Err(Reject::Unsupported),
    }
}

/// An IP+UDP packet from `src` to `dst`; `None` if the families differ or it is over `mtu`.
pub(crate) fn udp(src: SocketAddr, dst: SocketAddr, payload: &[u8], mtu: usize) -> Option<Vec<u8>> {
    let src_ip = match (src.ip(), dst.ip()) {
        // A reply named by its IPv4-mapped form still belongs to an IPv4 flow.
        (IpAddr::V6(v6), IpAddr::V4(_)) => IpAddr::V4(v6.to_ipv4_mapped()?),
        (ip, _) => ip,
    };
    let udp_len = UDP_HEADER + payload.len();
    let repr = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let caps = ChecksumCapabilities::default();
    let mut out;
    match (src_ip, dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let ip = Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: HOP_LIMIT,
            };
            let len = ip.buffer_len() + udp_len;
            if len > mtu {
                return None;
            }
            out = vec![0u8; len];
            let mut packet = Ipv4Packet::new_unchecked(&mut out[..]);
            ip.emit(&mut packet, &caps);
            emit_udp(
                &repr,
                packet.payload_mut(),
                s.into(),
                d.into(),
                payload,
                &caps,
            );
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let ip = Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: HOP_LIMIT,
            };
            let len = ip.buffer_len() + udp_len;
            if len > mtu {
                return None;
            }
            out = vec![0u8; len];
            let mut packet = Ipv6Packet::new_unchecked(&mut out[..]);
            ip.emit(&mut packet);
            emit_udp(
                &repr,
                packet.payload_mut(),
                s.into(),
                d.into(),
                payload,
                &caps,
            );
        }
        _ => return None,
    }
    Some(out)
}

fn emit_udp(
    repr: &UdpRepr,
    buf: &mut [u8],
    src: IpAddress,
    dst: IpAddress,
    payload: &[u8],
    caps: &ChecksumCapabilities,
) {
    let mut udp = UdpPacket::new_unchecked(buf);
    repr.emit(
        &mut udp,
        &src,
        &dst,
        payload.len(),
        |p| p.copy_from_slice(payload),
        caps,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn udp_roundtrip_v4_and_v6() {
        for (src, dst) in [
            (v4("8.8.8.8:53"), v4("10.0.0.2:40000")),
            (v4("[2001:db8::1]:3478"), v4("[fd00::2]:5000")),
        ] {
            let packet = udp(src, dst, b"hello", 1400).unwrap();
            assert_eq!(
                parse(&packet),
                Ok(Inbound::Udp {
                    src,
                    dst,
                    payload: b"hello"
                })
            );
        }
    }

    #[test]
    fn udp_reply_from_mapped_address_and_mismatched_family() {
        let packet = udp(v4("[::ffff:1.2.3.4]:53"), v4("10.0.0.2:4000"), b"x", 1400).unwrap();
        let Ok(Inbound::Udp { src, .. }) = parse(&packet) else {
            panic!("not UDP")
        };
        assert_eq!(src, v4("1.2.3.4:53"));
        assert_eq!(
            udp(v4("[2001:db8::1]:53"), v4("10.0.0.2:4000"), b"x", 1400),
            None
        );
        assert_eq!(
            udp(v4("1.2.3.4:53"), v4("[fd00::2]:4000"), b"x", 1400),
            None
        );
    }

    #[test]
    fn udp_over_mtu_is_not_built() {
        let payload = [0u8; 1400 - 20 - 8];
        assert!(udp(v4("1.2.3.4:53"), v4("10.0.0.2:4000"), &payload, 1400).is_some());
        let payload = [0u8; 1400 - 20 - 8 + 1];
        assert_eq!(
            udp(v4("1.2.3.4:53"), v4("10.0.0.2:4000"), &payload, 1400),
            None
        );
    }

    #[test]
    fn a01_t4_broken_packets_are_rejected_without_panic() {
        let good = udp(v4("8.8.8.8:53"), v4("10.0.0.2:40000"), b"hello", 1400).unwrap();
        // Every truncation of a valid packet.
        for n in 0..good.len() {
            assert!(parse(&good[..n]).is_err(), "truncated to {n}");
        }
        // Total length larger than the buffer.
        let mut long = good.clone();
        long[2..4].copy_from_slice(&2000u16.to_be_bytes());
        assert_eq!(parse(&long), Err(Reject::Malformed));
        // UDP length larger than the IP payload.
        let mut udp_len = good.clone();
        udp_len[24..26].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(parse(&udp_len), Err(Reject::Malformed));
        // Unknown IP version.
        let mut version = good.clone();
        version[0] = 0x55;
        assert_eq!(parse(&version), Err(Reject::Malformed));
        // A fragment.
        let mut fragment = good.clone();
        fragment[6] |= 0x20;
        assert_eq!(parse(&fragment), Err(Reject::Fragment));
        // ICMP.
        let mut icmp = good.clone();
        icmp[9] = 1;
        assert_eq!(parse(&icmp), Err(Reject::Unsupported));
        // Arbitrary bytes.
        let mut x: u32 = 0x9e37_79b9;
        for len in 0..200 {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = parse(&junk);
            for first in [0x45, 0x60] {
                let mut j = junk.clone();
                if let Some(b) = j.first_mut() {
                    *b = first;
                }
                let _ = parse(&j);
            }
        }
    }
}

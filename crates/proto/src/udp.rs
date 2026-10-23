//! `UdpDatagram`: one UDP packet carried in a QUIC DATAGRAM or a mux `DATAGRAM` frame.
//!
//! The carrier delivers whole datagrams, so the payload is everything after the header and a
//! short input is [`DecodeError::Truncated`], never `Incomplete`.

use bytes::{BufMut, Bytes};

use crate::addr::TargetAddr;
use crate::reader::Reader;
use crate::{DecodeError, EncodeError, varint};

const HAS_ADDR: u8 = 0x01;

/// UDP packet within a UDP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    /// UDP session, chosen by the client and unique within the session.
    pub session_id: u64,
    /// Destination (client → server) or source (server → client); `None` reuses the last one.
    pub addr: Option<TargetAddr>,
    /// Packet payload.
    pub payload: Bytes,
}

impl UdpDatagram {
    /// Appends the encoded datagram; writes nothing on error.
    pub fn encode(&self, out: &mut impl BufMut) -> Result<(), EncodeError> {
        varint::encoded_len(self.session_id)?;
        if let Some(addr) = &self.addr {
            addr.check()?;
        }
        varint::encode(self.session_id, out)?;
        match &self.addr {
            Some(addr) => {
                out.put_u8(HAS_ADDR);
                addr.encode(out)?;
            }
            None => out.put_u8(0),
        }
        out.put_slice(&self.payload);
        Ok(())
    }

    /// Decodes a whole datagram; the payload shares `buf` without copying.
    ///
    /// On error the caller drops the datagram and keeps the connection.
    pub fn decode(buf: Bytes) -> Result<Self, DecodeError> {
        let mut r = Reader::new(&buf);
        let (session_id, addr) = read_header(&mut r).map_err(|e| match e {
            DecodeError::Incomplete => DecodeError::Truncated,
            e => e,
        })?;
        let payload = buf.slice(r.position()..);
        Ok(Self {
            session_id,
            addr,
            payload,
        })
    }
}

fn read_header(r: &mut Reader<'_>) -> Result<(u64, Option<TargetAddr>), DecodeError> {
    let session_id = r.varint()?;
    let addr = match r.u8()? {
        0 => None,
        HAS_ADDR => Some(TargetAddr::read(r)?),
        flags => return Err(DecodeError::ReservedFlags(flags & !HAS_ADDR)),
    };
    Ok((session_id, addr))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::addr::Host;

    fn enc(d: &UdpDatagram) -> Bytes {
        let mut out = Vec::new();
        d.encode(&mut out).unwrap();
        out.into()
    }

    #[test]
    fn c03_t1_datagram_roundtrips_with_and_without_addr() {
        let samples = [
            UdpDatagram {
                session_id: 1,
                addr: Some(TargetAddr {
                    host: Host::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    port: 53,
                }),
                payload: Bytes::from_static(b"dns query"),
            },
            UdpDatagram {
                session_id: 300,
                addr: Some(TargetAddr {
                    host: Host::Domain("stun.example.org".into()),
                    port: 3478,
                }),
                payload: Bytes::new(),
            },
            UdpDatagram {
                session_id: varint::MAX,
                addr: None,
                payload: Bytes::from_static(&[0; 1200]),
            },
        ];
        for d in samples {
            let bytes = enc(&d);
            let decoded = UdpDatagram::decode(bytes.clone()).unwrap();
            assert_eq!(decoded, d);
            // Zero-copy: the payload points into the received buffer.
            let start = bytes.len() - d.payload.len();
            assert_eq!(decoded.payload.as_ptr(), bytes[start..].as_ptr());
        }
        // Without an address the header is just session_id and flags.
        let d = UdpDatagram {
            session_id: 5,
            addr: None,
            payload: Bytes::from_static(b"rtp"),
        };
        assert_eq!(&enc(&d)[..], &[0x05, 0x00, b'r', b't', b'p']);
    }

    #[test]
    fn malformed_datagram_is_rejected() {
        let cases: [(&'static [u8], DecodeError); 5] = [
            (&[], DecodeError::Truncated),
            (&[0x05], DecodeError::Truncated),
            (&[0x05, HAS_ADDR, 0x01, 8, 8], DecodeError::Truncated),
            (&[0x05, 0x02, b'x'], DecodeError::ReservedFlags(0x02)),
            (
                &[0x05, 0x81, 0x01, 8, 8, 8, 8, 0, 53],
                DecodeError::ReservedFlags(0x80),
            ),
        ];
        for (bytes, err) in cases {
            assert_eq!(UdpDatagram::decode(Bytes::from_static(bytes)), Err(err));
        }
        let mut out = Vec::new();
        let d = UdpDatagram {
            session_id: varint::MAX + 1,
            addr: None,
            payload: Bytes::new(),
        };
        assert_eq!(
            d.encode(&mut out),
            Err(EncodeError::VarintOverflow(varint::MAX + 1))
        );
        assert!(out.is_empty());
    }

    #[test]
    fn truncated_header_is_truncated() {
        let addrs = [
            Host::V4(Ipv4Addr::new(1, 2, 3, 4)),
            Host::V6(std::net::Ipv6Addr::LOCALHOST),
            Host::Domain("example.com".into()),
        ];
        for host in addrs {
            let d = UdpDatagram {
                session_id: 300,
                addr: Some(TargetAddr { host, port: 53 }),
                payload: Bytes::new(),
            };
            let bytes = enc(&d);
            // With an empty payload every cut falls inside the header.
            for cut in 0..bytes.len() {
                assert_eq!(
                    UdpDatagram::decode(bytes.slice(..cut)),
                    Err(DecodeError::Truncated),
                    "{d:?} cut at {cut}"
                );
            }
        }
    }

    #[test]
    fn invalid_addr_in_datagram_is_reported_as_such() {
        let cases: [(&'static [u8], DecodeError); 2] = [
            (
                &[0x05, HAS_ADDR, 0x02, 0, 0],
                DecodeError::UnknownAddrType(0x02),
            ),
            (
                &[0x05, HAS_ADDR, 0x03, 0x00, 0, 53],
                DecodeError::InvalidDomain,
            ),
        ];
        for (bytes, err) in cases {
            assert_eq!(UdpDatagram::decode(Bytes::from_static(bytes)), Err(err));
        }
    }

    #[test]
    fn invalid_addr_writes_nothing_on_encode() {
        for name in [String::new(), "x".repeat(256)] {
            let len = name.len();
            let d = UdpDatagram {
                session_id: 1,
                addr: Some(TargetAddr {
                    host: Host::Domain(name),
                    port: 53,
                }),
                payload: Bytes::from_static(b"q"),
            };
            let mut out = Vec::new();
            assert_eq!(
                d.encode(&mut out),
                Err(EncodeError::InvalidDomainLength(len))
            );
            assert!(out.is_empty());
        }
    }
}

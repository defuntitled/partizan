//! `Connect` / `ConnectResult`: the header that opens every proxied TCP stream.
//!
//! Raw stream data follows the header, so `decode` returns how many bytes it consumed.

use bytes::BufMut;

use crate::addr::TargetAddr;
use crate::reader::Reader;
use crate::{DecodeError, EncodeError, varint};

/// Largest allowed `padding_len`; bigger values are rejected before waiting for the bytes.
pub const MAX_PADDING: usize = 1024;

const TYPE_CONNECT: u64 = 0x01;
const TYPE_CONNECT_RESULT: u64 = 0x02;

/// Client → server: open a TCP connection to `addr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// Destination.
    pub addr: TargetAddr,
    /// Number of padding bytes; zeros on encode, contents ignored on decode.
    pub padding: usize,
}

impl Connect {
    /// Appends the encoded header; writes nothing on error.
    pub fn encode(&self, out: &mut impl BufMut) -> Result<(), EncodeError> {
        self.addr.check()?;
        check_padding(self.padding)?;
        varint::encode(TYPE_CONNECT, out)?;
        self.addr.encode(out)?;
        write_padding(self.padding, out)
    }

    /// Decodes the header from the front of `buf`, returning it and the bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut r = Reader::new(buf);
        expect_type(&mut r, TYPE_CONNECT)?;
        let addr = TargetAddr::read(&mut r)?;
        let padding = read_padding(&mut r)?;
        Ok((Self { addr, padding }, r.position()))
    }
}

/// Outcome of a `Connect`; codes other than `Ok` match SOCKS5 REP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectStatus {
    /// Connected.
    Ok = 0x00,
    /// General failure.
    GeneralFailure = 0x01,
    /// Denied by the egress policy.
    NotAllowed = 0x02,
    /// Network unreachable.
    NetworkUnreachable = 0x03,
    /// Host unreachable.
    HostUnreachable = 0x04,
    /// Connection refused by the target.
    ConnectionRefused = 0x05,
    /// Connect timed out.
    TtlExpired = 0x06,
    /// Command not supported.
    CommandNotSupported = 0x07,
    /// Address type not supported.
    AddrTypeNotSupported = 0x08,
}

impl TryFrom<u8> for ConnectStatus {
    type Error = DecodeError;

    fn try_from(code: u8) -> Result<Self, DecodeError> {
        Ok(match code {
            0x00 => Self::Ok,
            0x01 => Self::GeneralFailure,
            0x02 => Self::NotAllowed,
            0x03 => Self::NetworkUnreachable,
            0x04 => Self::HostUnreachable,
            0x05 => Self::ConnectionRefused,
            0x06 => Self::TtlExpired,
            0x07 => Self::CommandNotSupported,
            0x08 => Self::AddrTypeNotSupported,
            other => return Err(DecodeError::UnknownStatus(other)),
        })
    }
}

/// Server → client: result of a `Connect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    /// Outcome.
    pub status: ConnectStatus,
    /// Number of padding bytes; zeros on encode, contents ignored on decode.
    pub padding: usize,
}

impl ConnectResult {
    /// Appends the encoded header; writes nothing on error.
    pub fn encode(&self, out: &mut impl BufMut) -> Result<(), EncodeError> {
        check_padding(self.padding)?;
        varint::encode(TYPE_CONNECT_RESULT, out)?;
        out.put_u8(self.status as u8);
        write_padding(self.padding, out)
    }

    /// Decodes the header from the front of `buf`, returning it and the bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut r = Reader::new(buf);
        expect_type(&mut r, TYPE_CONNECT_RESULT)?;
        let status = ConnectStatus::try_from(r.u8()?)?;
        let padding = read_padding(&mut r)?;
        Ok((Self { status, padding }, r.position()))
    }
}

fn expect_type(r: &mut Reader<'_>, expected: u64) -> Result<(), DecodeError> {
    match r.varint()? {
        t if t == expected => Ok(()),
        t => Err(DecodeError::UnexpectedType(t)),
    }
}

fn check_padding(len: usize) -> Result<(), EncodeError> {
    if len > MAX_PADDING {
        return Err(EncodeError::PaddingLimit(len));
    }
    Ok(())
}

fn write_padding(len: usize, out: &mut impl BufMut) -> Result<(), EncodeError> {
    varint::encode(len as u64, out)?;
    out.put_bytes(0, len);
    Ok(())
}

fn read_padding(r: &mut Reader<'_>) -> Result<usize, DecodeError> {
    let len = r.varint()?;
    if len > MAX_PADDING as u64 {
        return Err(DecodeError::LengthLimit(len));
    }
    let len = len as usize;
    r.bytes(len)?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::addr::Host;

    fn connect(host: Host, padding: usize) -> Connect {
        Connect {
            addr: TargetAddr { host, port: 443 },
            padding,
        }
    }

    fn samples() -> Vec<Connect> {
        vec![
            connect(Host::V4(Ipv4Addr::new(93, 184, 216, 34)), 0),
            connect(Host::V6(Ipv6Addr::LOCALHOST), 7),
            connect(Host::Domain("example.com".into()), 0),
            connect(Host::Domain("x".repeat(255)), MAX_PADDING),
        ]
    }

    fn enc(c: &Connect) -> Vec<u8> {
        let mut out = Vec::new();
        c.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn c02_t3_connect_roundtrips_all_address_types() {
        for c in samples() {
            let bytes = enc(&c);
            assert_eq!(Connect::decode(&bytes), Ok((c, bytes.len())));
        }
        for status in (0..=8).map(|code| ConnectStatus::try_from(code).unwrap()) {
            let r = ConnectResult { status, padding: 3 };
            let mut bytes = Vec::new();
            r.encode(&mut bytes).unwrap();
            assert_eq!(ConnectResult::decode(&bytes), Ok((r, bytes.len())));
        }
    }

    #[test]
    fn c02_t4_truncated_connect_is_incomplete() {
        for c in samples() {
            let bytes = enc(&c);
            for cut in 0..bytes.len() {
                assert_eq!(
                    Connect::decode(&bytes[..cut]),
                    Err(DecodeError::Incomplete),
                    "{c:?} cut at {cut}"
                );
            }
        }
        let mut bytes = Vec::new();
        ConnectResult {
            status: ConnectStatus::Ok,
            padding: 2,
        }
        .encode(&mut bytes)
        .unwrap();
        for cut in 0..bytes.len() {
            assert_eq!(
                ConnectResult::decode(&bytes[..cut]),
                Err(DecodeError::Incomplete)
            );
        }
    }

    #[test]
    fn c02_t5_domain_over_255_bytes_is_rejected_on_encode() {
        for name in ["x".repeat(256), String::new()] {
            let len = name.len();
            let mut out = Vec::new();
            assert_eq!(
                connect(Host::Domain(name), 0).encode(&mut out),
                Err(EncodeError::InvalidDomainLength(len))
            );
            assert!(out.is_empty(), "nothing written on error");
        }
    }

    #[test]
    fn c02_t6_padding_is_decoded_and_ignored() {
        // Connect to 1.2.3.4:80 with 3 bytes of non-zero padding, then stream data.
        let bytes = [
            0x01, 0x01, 1, 2, 3, 4, 0x00, 0x50, 0x03, 0xaa, 0xbb, 0xcc, b'G', b'E',
        ];
        let (c, used) = Connect::decode(&bytes).unwrap();
        let expected = Connect {
            addr: TargetAddr {
                host: Host::V4(Ipv4Addr::new(1, 2, 3, 4)),
                port: 80,
            },
            padding: 3,
        };
        assert_eq!(c, expected);
        assert_eq!(
            &bytes[used..],
            b"GE",
            "data after the header is left untouched"
        );

        let bytes = [0x02, 0x05, 0x02, 0xff, 0xff];
        let expected = ConnectResult {
            status: ConnectStatus::ConnectionRefused,
            padding: 2,
        };
        assert_eq!(ConnectResult::decode(&bytes), Ok((expected, 5)));
    }

    #[test]
    fn garbage_connect_is_rejected() {
        let cases: [(&[u8], DecodeError); 6] = [
            (&[0x02, 0x01], DecodeError::UnexpectedType(0x02)),
            (&[0x01, 0x02, 0, 0], DecodeError::UnknownAddrType(0x02)),
            (&[0x01, 0x03, 0x00, 0, 80, 0], DecodeError::InvalidDomain),
            (
                &[0x01, 0x03, 0x01, 0xff, 0, 80, 0],
                DecodeError::InvalidDomain,
            ),
            // padding_len = 1025 is rejected without waiting for the padding bytes.
            (
                &[0x01, 0x01, 1, 2, 3, 4, 0, 80, 0x44, 0x01],
                DecodeError::LengthLimit(1025),
            ),
            (&[0x40, 0x01], DecodeError::NonMinimalVarint),
        ];
        for (bytes, err) in cases {
            assert_eq!(Connect::decode(bytes), Err(err), "{bytes:02x?}");
        }
        assert_eq!(
            ConnectResult::decode(&[0x02, 0x09, 0x00]),
            Err(DecodeError::UnknownStatus(0x09))
        );
        let mut out = Vec::new();
        let padded = connect(Host::V4(Ipv4Addr::LOCALHOST), MAX_PADDING + 1);
        assert_eq!(
            padded.encode(&mut out),
            Err(EncodeError::PaddingLimit(MAX_PADDING + 1))
        );
        assert!(out.is_empty());
    }
}

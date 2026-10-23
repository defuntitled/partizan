//! Destination address shared by `Connect` and `UdpDatagram`, coded as in SOCKS5.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::BufMut;

use crate::reader::Reader;
use crate::{DecodeError, EncodeError};

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Destination host; a domain name is resolved by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// IPv4 address.
    V4(Ipv4Addr),
    /// IPv6 address.
    V6(Ipv6Addr),
    /// Domain name, 1–255 bytes of UTF-8.
    Domain(String),
}

/// Destination host and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetAddr {
    /// Destination host.
    pub host: Host,
    /// Destination port.
    pub port: u16,
}

impl TargetAddr {
    /// Validates the address without writing it.
    pub(crate) fn check(&self) -> Result<(), EncodeError> {
        if let Host::Domain(name) = &self.host
            && !(1..=255).contains(&name.len())
        {
            return Err(EncodeError::InvalidDomainLength(name.len()));
        }
        Ok(())
    }

    /// Writes `addr_type, addr, port`.
    pub(crate) fn encode(&self, out: &mut impl BufMut) -> Result<(), EncodeError> {
        self.check()?;
        match &self.host {
            Host::V4(ip) => {
                out.put_u8(ATYP_IPV4);
                out.put_slice(&ip.octets());
            }
            Host::V6(ip) => {
                out.put_u8(ATYP_IPV6);
                out.put_slice(&ip.octets());
            }
            Host::Domain(name) => {
                out.put_u8(ATYP_DOMAIN);
                out.put_u8(name.len() as u8);
                out.put_slice(name.as_bytes());
            }
        }
        out.put_u16(self.port);
        Ok(())
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let host = match r.u8()? {
            ATYP_IPV4 => Host::V4(Ipv4Addr::from(r.array::<4>()?)),
            ATYP_IPV6 => Host::V6(Ipv6Addr::from(r.array::<16>()?)),
            ATYP_DOMAIN => {
                let len = r.u8()?;
                let raw = r.bytes(len.into())?;
                if raw.is_empty() {
                    return Err(DecodeError::InvalidDomain);
                }
                let name = std::str::from_utf8(raw).map_err(|_| DecodeError::InvalidDomain)?;
                Host::Domain(name.to_owned())
            }
            other => return Err(DecodeError::UnknownAddrType(other)),
        };
        let port = r.u16_be()?;
        Ok(Self { host, port })
    }
}

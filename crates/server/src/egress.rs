//! Egress policy: which destination addresses a device may reach. Guards the VPS network
//! against SSRF; checked on resolved addresses, so DNS cannot point around it.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de};

/// Address block such as `10.0.0.0/8` or `fd00::/8`; a bare address is a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// True if `ip` is inside the block.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => mask_eq(&net.octets(), &ip.octets(), self.prefix),
            (IpAddr::V6(net), IpAddr::V6(ip)) => mask_eq(&net.octets(), &ip.octets(), self.prefix),
            _ => false,
        }
    }
}

fn mask_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let (bytes, bits) = (usize::from(prefix / 8), prefix % 8);
    if a[..bytes] != b[..bytes] {
        return false;
    }
    bits == 0 || (a[bytes] ^ b[bytes]) >> (8 - bits) == 0
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let net: IpAddr = addr.parse().map_err(|_| format!("bad address in {s:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|&p| p <= max)
                .ok_or_else(|| format!("bad prefix in {s:?}"))?,
        };
        Ok(Self { net, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(de::Error::custom)
    }
}

/// Which destinations are allowed.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    deny_private: bool,
    allow: Vec<Cidr>,
}

impl EgressPolicy {
    /// Policy from `[egress]`.
    pub fn new(deny_private: bool, allow: Vec<Cidr>) -> Self {
        Self {
            deny_private,
            allow,
        }
    }

    /// True if a device may connect to `ip`.
    pub fn allows(&self, ip: IpAddr) -> bool {
        !self.deny_private
            || !is_internal(canonical(ip))
            || self.allow.iter().any(|c| c.contains(ip))
    }
}

/// IPv4-mapped and NAT64 addresses as the IPv4 address they reach.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let s = v6.segments();
            // 64:ff9b::/96 (RFC 6052).
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            }
            ip
        }
        v4 => v4,
    }
}

/// Addresses that lead into the VPS's own networks rather than the internet.
fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // Includes cloud metadata 169.254.169.254.
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && o[1] & 0xc0 == 64) // CGNAT 100.64.0.0/10.
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || s[0] & 0xfe00 == 0xfc00 // Unique local fc00::/7.
                || s[0] & 0xffc0 == 0xfe80 // Link-local fe80::/10.
                || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) // AWS IPv6 metadata.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn internal_ranges_are_denied_and_internet_allowed() {
        let policy = EgressPolicy::new(true, Vec::new());
        for denied in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!policy.allows(ip(denied)), "{denied}");
        }
        for allowed in [
            "1.1.1.1",
            "100.128.0.1",
            "172.32.0.1",
            "2001:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(policy.allows(ip(allowed)), "{allowed}");
        }
        assert!(EgressPolicy::new(false, Vec::new()).allows(ip("127.0.0.1")));
    }

    #[test]
    fn allow_list_makes_exceptions() {
        let allow = vec!["10.8.0.0/16".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        let policy = EgressPolicy::new(true, allow);
        assert!(policy.allows(ip("10.8.200.1")));
        assert!(!policy.allows(ip("10.9.0.1")));
        assert!(policy.allows(ip("127.0.0.1")));
        assert!(policy.allows(ip("::ffff:127.0.0.1")));
        assert!(!policy.allows(ip("127.0.0.2")));
    }

    #[test]
    fn cidr_parsing() {
        let c: Cidr = "192.168.0.0/23".parse().unwrap();
        assert!(c.contains(ip("192.168.1.255")));
        assert!(!c.contains(ip("192.168.2.0")));
        assert_eq!(c.to_string(), "192.168.0.0/23");
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("fd00::/129".parse::<Cidr>().is_err());
        assert!("bogus/8".parse::<Cidr>().is_err());
        let v6: Cidr = "fd00::/8".parse().unwrap();
        assert!(v6.contains(ip("fdff::1")));
        assert!(!v6.contains(ip("10.0.0.1")));
    }
}

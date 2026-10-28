//! Split tunneling: which destinations go through the tunnel and which go direct.
//!
//! The system routes of the interface are the first line; this filter is the second, for
//! packets that reached the interface anyway. A connection is decided once, at its SYN; a UDP
//! datagram is decided on its own destination. DNS always goes through the tunnel, whatever
//! the mode, so names never leak to the local network.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// DNS, DNS over TCP, DNS over TLS.
const DNS_PORTS: [u16; 2] = [53, 853];

/// An address with a prefix length; host bits are zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// `None` if `prefix` is longer than the address.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let max = max_prefix(addr);
        if prefix > max {
            return None;
        }
        let addr = match addr {
            IpAddr::V4(ip) => IpAddr::V4((u32::from(ip) & mask32(prefix)).into()),
            IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & mask128(prefix)).into()),
        };
        Some(Self { addr, prefix })
    }

    /// Network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is in this network; never across families.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => u32::from(ip) & mask32(self.prefix) == net.into(),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & mask128(self.prefix) == net.into()
            }
            _ => false,
        }
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// A string that is neither an address nor `address/prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseNetError;

impl fmt::Display for ParseNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an IP address or CIDR network")
    }
}

impl std::error::Error for ParseNetError {}

impl FromStr for IpNet {
    type Err = ParseNetError;

    /// `203.0.113.7` (a `/32`), `99.84.0.0/16`, `2606:4700::/32`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| ParseNetError)?;
        let prefix = match prefix {
            // Digits only: `u8::from_str` would also take `+16`.
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse().map_err(|_| ParseNetError)?
            }
            Some(_) => return Err(ParseNetError),
            None => max_prefix(addr),
        };
        Self::new(addr, prefix).ok_or(ParseNetError)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// What the listed networks mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitMode {
    /// Only the listed networks go through the tunnel, the rest goes direct.
    Include,
    /// Everything goes through the tunnel except the listed networks.
    #[default]
    Exclude,
}

/// Split tunneling rules. The default, `Exclude` with no networks, tunnels everything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitConfig {
    /// How `routes` is read.
    pub mode: SplitMode,
    /// Networks and single addresses the mode applies to.
    pub routes: Vec<IpNet>,
}

/// Where traffic to a destination goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Path {
    /// Through the partizan tunnel.
    Tunnel,
    /// Out of the device's own network, bypassing the tunnel.
    Direct,
}

/// Compiled rules: per prefix length, the set of networks, longest prefixes first.
#[derive(Debug, Default)]
pub(crate) struct Rules {
    mode: SplitMode,
    v4: Vec<(u8, HashSet<u32>)>,
    v6: Vec<(u8, HashSet<u128>)>,
}

impl Rules {
    pub(crate) fn new(config: &SplitConfig) -> Self {
        let mut rules = Self {
            mode: config.mode,
            ..Self::default()
        };
        for net in &config.routes {
            match net.addr {
                IpAddr::V4(ip) => insert(&mut rules.v4, net.prefix, u32::from(ip)),
                IpAddr::V6(ip) => insert(&mut rules.v6, net.prefix, u128::from(ip)),
            }
        }
        rules
            .v4
            .sort_by_key(|&(prefix, _)| std::cmp::Reverse(prefix));
        rules
            .v6
            .sort_by_key(|&(prefix, _)| std::cmp::Reverse(prefix));
        rules
    }

    /// The most specific listed network holding `ip`.
    pub(crate) fn matching(&self, ip: IpAddr) -> Option<IpNet> {
        match ip {
            IpAddr::V4(ip) => {
                let bits = u32::from(ip);
                self.v4
                    .iter()
                    .find(|(prefix, nets)| nets.contains(&(bits & mask32(*prefix))))
                    .and_then(|&(prefix, _)| IpNet::new(ip.into(), prefix))
            }
            IpAddr::V6(ip) => {
                let bits = u128::from(ip);
                self.v6
                    .iter()
                    .find(|(prefix, nets)| nets.contains(&(bits & mask128(*prefix))))
                    .and_then(|&(prefix, _)| IpNet::new(ip.into(), prefix))
            }
        }
    }

    /// Where traffic to `dst` goes.
    pub(crate) fn path(&self, dst: SocketAddr) -> Path {
        if DNS_PORTS.contains(&dst.port()) {
            return Path::Tunnel;
        }
        let listed = self.matching(dst.ip()).is_some();
        match (self.mode, listed) {
            (SplitMode::Include, true) | (SplitMode::Exclude, false) => Path::Tunnel,
            _ => Path::Direct,
        }
    }
}

fn insert<T: std::hash::Hash + Eq>(table: &mut Vec<(u8, HashSet<T>)>, prefix: u8, net: T) {
    match table.iter_mut().find(|(p, _)| *p == prefix) {
        Some((_, nets)) => {
            nets.insert(net);
        }
        None => table.push((prefix, HashSet::from([net]))),
    }
}

/// The live rules and traffic counters, shared between the stack and its owner. Rules can be
/// replaced while the stack runs; connections already open keep their path.
#[derive(Default)]
pub struct Split {
    rules: RwLock<Arc<Rules>>,
    tunnel: PathCounters,
    direct: PathCounters,
}

#[derive(Default)]
struct PathCounters {
    sent: AtomicU64,
    received: AtomicU64,
}

/// Payload bytes per path since the stack started. "Sent" is from the device's apps outward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SplitStats {
    /// Sent through the tunnel.
    pub tunnel_sent: u64,
    /// Received through the tunnel.
    pub tunnel_received: u64,
    /// Sent direct.
    pub direct_sent: u64,
    /// Received direct.
    pub direct_received: u64,
}

impl Split {
    /// Rules from `config`.
    pub fn new(config: &SplitConfig) -> Self {
        let split = Self::default();
        split.set(config);
        split
    }

    /// Replaces the rules; new connections and datagrams follow them at once.
    pub fn set(&self, config: &SplitConfig) {
        let rules = Arc::new(Rules::new(config));
        *self.rules.write().unwrap_or_else(|e| e.into_inner()) = rules;
    }

    /// Where traffic to `dst` goes under the current rules.
    pub fn path(&self, dst: SocketAddr) -> Path {
        self.rules().path(dst)
    }

    /// Traffic counters.
    pub fn stats(&self) -> SplitStats {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        SplitStats {
            tunnel_sent: get(&self.tunnel.sent),
            tunnel_received: get(&self.tunnel.received),
            direct_sent: get(&self.direct.sent),
            direct_received: get(&self.direct.received),
        }
    }

    pub(crate) fn rules(&self) -> Arc<Rules> {
        self.rules.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn counters(&self, path: Path) -> &PathCounters {
        match path {
            Path::Tunnel => &self.tunnel,
            Path::Direct => &self.direct,
        }
    }

    pub(crate) fn sent(&self, path: Path, bytes: usize) {
        if bytes > 0 {
            let c = &self.counters(path).sent;
            c.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    pub(crate) fn received(&self, path: Path, bytes: usize) {
        if bytes > 0 {
            let c = &self.counters(path).received;
            c.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn rules(mode: SplitMode, list: &[&str]) -> Rules {
        Rules::new(&SplitConfig {
            mode,
            routes: nets(list),
        })
    }

    fn at(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn nets_parse_normalize_and_reject_junk() {
        assert_eq!(
            "99.84.1.2/16".parse::<IpNet>().unwrap().to_string(),
            "99.84.0.0/16"
        );
        assert_eq!(
            "203.0.113.7".parse::<IpNet>().unwrap().to_string(),
            "203.0.113.7/32"
        );
        assert_eq!(
            "2606:4700::1".parse::<IpNet>().unwrap().to_string(),
            "2606:4700::1/128"
        );
        assert_eq!("0.0.0.0/0".parse::<IpNet>().unwrap().prefix(), 0);
        for junk in [
            "",
            "/",
            "1.2.3.4/",
            "1.2.3.4/33",
            "::/129",
            "1.2.3.4/+8",
            "1.2.3/8",
            "x/8",
            "1.2.3.4/8/8",
        ] {
            assert_eq!(junk.parse::<IpNet>(), Err(ParseNetError), "{junk:?}");
        }
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains("10.255.0.1".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        assert!(
            !net.contains("::a00:1".parse().unwrap()),
            "no family crossing"
        );
    }

    #[test]
    fn a02_t1_include_tunnels_only_listed_networks() {
        let r = rules(SplitMode::Include, &["99.84.0.0/16", "203.0.113.7"]);
        assert_eq!(r.path(at("99.84.10.1:443")), Path::Tunnel);
        assert_eq!(r.path(at("203.0.113.7:443")), Path::Tunnel);
        assert_eq!(r.path(at("203.0.113.8:443")), Path::Direct);
        assert_eq!(r.path(at("99.85.0.1:443")), Path::Direct);
    }

    #[test]
    fn a02_t2_exclude_tunnels_all_but_listed_networks() {
        let r = rules(SplitMode::Exclude, &["192.168.0.0/16"]);
        assert_eq!(r.path(at("192.168.1.10:80")), Path::Direct);
        assert_eq!(r.path(at("8.8.4.4:443")), Path::Tunnel);
    }

    #[test]
    fn a02_t3_ipv4_and_ipv6_rules_apply_separately() {
        let r = rules(SplitMode::Include, &["10.0.0.0/8", "2606:4700::/32"]);
        assert_eq!(r.path(at("10.1.2.3:443")), Path::Tunnel);
        assert_eq!(r.path(at("[2606:4700::1111]:443")), Path::Tunnel);
        assert_eq!(r.path(at("[2001:db8::1]:443")), Path::Direct);
        // 10.0.0.0/8 says nothing about the IPv6 range with the same leading bits.
        assert_eq!(r.path(at("[a00::1]:443")), Path::Direct);
        assert_eq!(r.path(at("[::ffff:10.1.2.3]:443")), Path::Direct);
        // A /0 of one family does not cover the other.
        let all_v4 = rules(SplitMode::Include, &["0.0.0.0/0"]);
        assert_eq!(all_v4.path(at("1.2.3.4:443")), Path::Tunnel);
        assert_eq!(all_v4.path(at("[2001:db8::1]:443")), Path::Direct);
    }

    #[test]
    fn a02_t4_empty_include_tunnels_nothing() {
        let r = rules(SplitMode::Include, &[]);
        assert_eq!(r.path(at("1.1.1.1:443")), Path::Direct);
        assert_eq!(r.path(at("[2001:db8::1]:443")), Path::Direct);
        let r = rules(SplitMode::Exclude, &[]);
        assert_eq!(r.path(at("1.1.1.1:443")), Path::Tunnel);
    }

    #[test]
    fn a02_t5_most_specific_overlapping_network_decides() {
        let r = rules(
            SplitMode::Include,
            &["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"],
        );
        let m = |ip: &str| r.matching(ip.parse().unwrap()).map(|n| n.to_string());
        assert_eq!(m("10.1.2.3").as_deref(), Some("10.1.2.0/24"));
        assert_eq!(m("10.1.3.3").as_deref(), Some("10.1.0.0/16"));
        assert_eq!(m("10.2.0.1").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(m("11.0.0.1"), None);
        let r6 = rules(SplitMode::Exclude, &["2001:db8::/32", "2001:db8:1::/48"]);
        assert_eq!(
            r6.matching("2001:db8:1::5".parse().unwrap()),
            Some("2001:db8:1::/48".parse().unwrap())
        );
        // Duplicates and overlaps change nothing.
        let dup = rules(
            SplitMode::Include,
            &["10.0.0.0/8", "10.0.0.0/8", "10.9.9.9"],
        );
        assert_eq!(dup.path(at("10.9.9.9:80")), Path::Tunnel);
        assert_eq!(dup.path(at("10.0.0.1:80")), Path::Tunnel);
    }

    #[test]
    fn dns_always_goes_through_the_tunnel() {
        let r = rules(SplitMode::Include, &[]);
        assert_eq!(r.path(at("192.168.1.1:53")), Path::Tunnel);
        assert_eq!(r.path(at("1.1.1.1:853")), Path::Tunnel);
        let r = rules(SplitMode::Exclude, &["192.168.0.0/16"]);
        assert_eq!(r.path(at("192.168.1.1:53")), Path::Tunnel);
    }

    #[test]
    fn rules_are_replaced_in_place() {
        let split = Split::new(&SplitConfig::default());
        assert_eq!(split.path(at("1.1.1.1:443")), Path::Tunnel);
        split.set(&SplitConfig {
            mode: SplitMode::Include,
            routes: nets(&["9.9.9.9"]),
        });
        assert_eq!(split.path(at("1.1.1.1:443")), Path::Direct);
        assert_eq!(split.path(at("9.9.9.9:443")), Path::Tunnel);
    }
}

//! Client engine: session, transport fallback, reconnect and UDP sessions.
//!
//! Takes abstract `TcpRequest` / `UdpPacket` from a traffic source and knows nothing
//! about SOCKS5 or TUN.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn c01_t3_unsafe_is_forbidden() {
        // `forbid` cannot be relaxed by an inner `allow`, so the crate-level attribute is enough.
        // It must sit in the crate header (inner docs and attributes only), not in a block
        // comment or after the first item.
        let mut header = include_str!("lib.rs")
            .lines()
            .map(str::trim)
            .take_while(|l| l.is_empty() || l.starts_with("//!") || l.starts_with("#!["));
        assert!(header.any(|l| l == "#![forbid(unsafe_code)]"));
    }
}

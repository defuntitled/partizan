//! Hex, base64url and percent-encoding helpers for headers and the connection URI.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    out
}

/// Decodes exactly `N` bytes of lowercase hex.
pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0; N];
    for (i, pair) in s.as_chunks::<2>().0.iter().enumerate() {
        out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

pub(crate) fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes exactly `N` bytes of unpadded base64url, rejecting non-canonical input.
pub(crate) fn unbase64url<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != (N * 4).div_ceil(3) {
        return None;
    }
    let mut out = [0; N];
    match URL_SAFE_NO_PAD.decode_slice(s, &mut out) {
        Ok(n) if n == N => Some(out),
        _ => None,
    }
}

/// Percent-encodes everything except RFC 3986 unreserved characters and `/`.
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&hex(&[b]).to_ascii_uppercase());
        }
    }
    out
}

pub(crate) fn percent_decode(s: &str) -> Option<String> {
    let s = s.as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let pair = std::str::from_utf8(s.get(i + 1..i + 3)?).ok()?;
            out.push(unhex::<1>(&pair.to_ascii_lowercase())?[0]);
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_base64url_are_strict() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(unhex::<3>("00abff"), Some([0x00, 0xab, 0xff]));
        for bad in ["00ABff", "00abf", "00abfg", "00abff00"] {
            assert_eq!(unhex::<3>(bad), None, "{bad}");
        }
        let token = [0x5a; 32];
        let s = base64url(&token);
        assert_eq!(s.len(), 43);
        assert_eq!(unbase64url::<32>(&s), Some(token));
        // Padding, wrong length, standard alphabet and non-zero trailing bits are rejected.
        assert_eq!(unbase64url::<32>(&format!("{s}=")), None);
        assert_eq!(unbase64url::<32>(&s[..42]), None);
        assert_eq!(unbase64url::<3>("+/+/"), None);
        assert_eq!(unbase64url::<1>("AB"), None);
    }

    #[test]
    fn percent_encoding_roundtrips() {
        let s = "/api/v2 sync?x=1&y=ü";
        let enc = percent_encode(s);
        assert_eq!(enc, "/api/v2%20sync%3Fx%3D1%26y%3D%C3%BC");
        assert_eq!(percent_decode(&enc).as_deref(), Some(s));
        assert_eq!(percent_decode("%2f%2F").as_deref(), Some("//"));
        for bad in ["%", "%2", "%zz", "%ff"] {
            assert_eq!(percent_decode(bad), None, "{bad}");
        }
    }
}

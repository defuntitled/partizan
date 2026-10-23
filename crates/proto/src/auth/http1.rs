//! HTTP/1.1 `Upgrade` request and `101` response for the auth exchange over TCP+TLS; after the
//! response the connection switches to the mux.

use zeroize::Zeroizing;

use crate::auth::{Fields, ParseError};

/// Longest request or response head we buffer.
const MAX_HEAD: usize = 8 * 1024;

/// Request or status line plus fields with lowercase names.
pub(crate) struct Head {
    pub(crate) start_line: String,
    pub(crate) fields: Fields,
}

pub(crate) fn encode_request(
    authority: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> Zeroizing<Vec<u8>> {
    let start = [
        "GET ",
        path,
        " HTTP/1.1\r\nHost: ",
        authority,
        "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
    ];
    head_bytes(&start, extra)
}

pub(crate) fn encode_switching_protocols(extra: &[(&str, &str)]) -> Vec<u8> {
    let start =
        ["HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"];
    head_bytes(&start, extra).to_vec()
}

/// Concatenates the head into a buffer sized up front, so growing never leaves a copy of the
/// `authorization` value behind.
fn head_bytes(start: &[&str], fields: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    let len = start.iter().map(|s| s.len()).sum::<usize>()
        + fields
            .iter()
            .map(|(n, v)| n.len() + v.len() + 4)
            .sum::<usize>()
        + 2;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for part in start {
        out.extend_from_slice(part.as_bytes());
    }
    for (name, value) in fields {
        for part in [name, ": ", value, "\r\n"] {
            out.extend_from_slice(part.as_bytes());
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// RFC 9110 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Parses a head ending in an empty line; returns it and bytes consumed, or `None` until the
/// head is complete.
pub(crate) fn decode_head(buf: &[u8]) -> Result<Option<(Head, usize)>, ParseError> {
    const BAD_LINE: ParseError = ParseError::Malformed("bad header line");
    let window = &buf[..buf.len().min(MAX_HEAD)];
    let Some(end) = window.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= MAX_HEAD {
            Err(ParseError::TooLarge)
        } else {
            Ok(None)
        };
    };
    let text =
        std::str::from_utf8(&buf[..end]).map_err(|_| ParseError::Malformed("non-UTF-8 head"))?;
    let mut lines = text.split("\r\n");
    let start_line = lines.next().unwrap_or_default();
    // No bare CR, LF or other control bytes anywhere: they make where the head ends ambiguous.
    if start_line.bytes().any(|b| b.is_ascii_control()) {
        return Err(ParseError::Malformed("bad start line"));
    }
    let mut fields = Fields(Vec::new());
    for line in lines {
        // Obsolete line folding and bare names are rejected (RFC 9112 §5).
        let (name, value) = line.split_once(':').ok_or(BAD_LINE)?;
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(BAD_LINE);
        }
        if value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return Err(BAD_LINE);
        }
        fields.0.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    let head = Head {
        start_line: start_line.to_owned(),
        fields,
    };
    Ok(Some((head, end + 4)))
}

impl Head {
    fn has_token(&self, name: &str, token: &str) -> bool {
        self.fields
            .iter()
            .any(|(n, v)| n == name && v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// `Connection: Upgrade` and `Upgrade: websocket`.
    pub(crate) fn is_upgrade(&self) -> bool {
        self.has_token("connection", "upgrade") && self.has_token("upgrade", "websocket")
    }

    /// `GET <path> HTTP/1.1` with one `Host`, the websocket upgrade and no body; returns the
    /// path.
    pub(crate) fn upgrade_path(&self) -> Result<&str, ParseError> {
        let mut parts = self.start_line.split(' ');
        let (Some("GET"), Some(path), Some("HTTP/1.1"), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ParseError::Malformed("not an HTTP/1.1 GET"));
        };
        if self.fields.iter().filter(|(n, _)| n == "host").count() != 1 {
            return Err(ParseError::Malformed("need exactly one Host"));
        }
        // A body would be read as mux data, so a request that announces one is not ours.
        let has_body =
            |(n, _): &&(String, String)| n == "content-length" || n == "transfer-encoding";
        if self.fields.iter().any(|f| has_body(&f)) {
            return Err(ParseError::Malformed("upgrade request with a body"));
        }
        if !self.is_upgrade() {
            return Err(ParseError::Malformed("not a websocket upgrade"));
        }
        Ok(path)
    }

    /// Status code from `HTTP/1.1 <3 digits>[ <reason>]`.
    pub(crate) fn status(&self) -> Option<u16> {
        let rest = self.start_line.strip_prefix("HTTP/1.1 ")?;
        let (code, reason) = (rest.get(..3)?, &rest[3..]);
        let valid = code.bytes().all(|b| b.is_ascii_digit())
            && (reason.is_empty() || reason.starts_with(' '));
        valid.then(|| code.parse().ok()).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_request_roundtrips() {
        let mut wire =
            encode_request("cdn.example.com", "/api/v2/sync", &[("x-client", "v=1")]).to_vec();
        let len = wire.len();
        wire.extend_from_slice(b"mux bytes");
        let (head, used) = decode_head(&wire).unwrap().unwrap();
        assert_eq!(used, len);
        assert_eq!(head.upgrade_path(), Ok("/api/v2/sync"));
        assert!(
            head.fields
                .contains(&("host".into(), "cdn.example.com".into()))
        );
        assert!(head.fields.contains(&("x-client".into(), "v=1".into())));
        for cut in 0..len {
            assert!(decode_head(&wire[..cut]).unwrap().is_none(), "cut at {cut}");
        }
        let (head, _) = decode_head(&encode_switching_protocols(&[]))
            .unwrap()
            .unwrap();
        assert_eq!(head.status(), Some(101));
    }

    #[test]
    fn malformed_heads_are_rejected() {
        let cases: [&[u8]; 4] = [
            b"GET / HTTP/1.1\r\n folded: x\r\n\r\n",
            b"GET / HTTP/1.1\r\nno-colon\r\n\r\n",
            b"GET / HTTP/1.1\r\nbad name: x\r\n\r\n",
            b"GET / HTTP/1.1\r\n\xff: x\r\n\r\n",
        ];
        for wire in cases {
            assert!(decode_head(wire).is_err(), "{wire:?}");
        }
        // Not an upgrade, or the wrong method or version.
        for wire in [
            &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            b"GET / HTTP/1.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        ] {
            let (head, _) = decode_head(wire).unwrap().unwrap();
            assert!(head.upgrade_path().is_err());
        }
        // A head that never ends stops at the limit.
        assert_eq!(
            decode_head(&vec![b'a'; MAX_HEAD]).err(),
            Some(ParseError::TooLarge)
        );
    }

    #[test]
    fn ambiguous_requests_are_rejected() {
        let upgrade = "Connection: Upgrade\r\nUpgrade: websocket\r\n";
        let cases = [
            format!("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n{upgrade}\r\n"),
            format!("GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n{upgrade}\r\n"),
            format!("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n{upgrade}\r\n"),
            format!("GET / HTTP/1.1\r\n{upgrade}\r\n"),
        ];
        for wire in &cases {
            let (head, _) = decode_head(wire.as_bytes()).unwrap().unwrap();
            assert!(head.upgrade_path().is_err(), "{wire:?}");
        }
        // Bare CR in the start line, a name or a value.
        for wire in [
            &b"GET /\r HTTP/1.1\r\nHost: a\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHo\rst: a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n",
        ] {
            assert!(decode_head(wire).is_err(), "{wire:?}");
        }
    }

    #[test]
    fn status_line_is_strict() {
        let status = |line: &str| {
            let wire = format!("{line}\r\n\r\n");
            decode_head(wire.as_bytes()).unwrap().unwrap().0.status()
        };
        assert_eq!(status("HTTP/1.1 101 Switching Protocols"), Some(101));
        assert_eq!(status("HTTP/1.1 101"), Some(101));
        assert_eq!(status("HTTP/1.1 1010 x"), None);
        assert_eq!(status("HTTP/1.1 10"), None);
        assert_eq!(status("HTTP/1.0 101 x"), None);
    }

    #[test]
    fn head_at_exactly_the_limit_is_accepted() {
        let prefix = "GET / HTTP/1.1\r\nx: ";
        let pad = MAX_HEAD - prefix.len() - 4;
        let wire = format!("{prefix}{}\r\n\r\n", "a".repeat(pad));
        assert_eq!(wire.len(), MAX_HEAD);
        assert!(decode_head(wire.as_bytes()).unwrap().is_some());
        let wire = format!("{prefix}{}\r\n\r\n", "a".repeat(pad + 1));
        assert_eq!(
            decode_head(wire.as_bytes()).err(),
            Some(ParseError::TooLarge)
        );
    }
}

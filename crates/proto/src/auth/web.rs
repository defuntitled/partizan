//! Plain web requests and responses, for the masquerade site that answers everything that is
//! not a valid auth request.

use super::{h3, http1};

/// The bytes are not an HTTP request of the expected version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an HTTP request")]
pub struct NotHttp;

/// A request's method and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRequest {
    /// `GET`, `HEAD`, …
    pub method: String,
    /// Request target as sent.
    pub path: String,
    /// The client asked to close after this response (HTTP/1.x).
    pub close: bool,
}

/// Parses an HTTP/1.x request head; returns it and the bytes it took, `None` until complete,
/// `Err` for anything that is not HTTP/1.x.
pub fn parse_http1(buf: &[u8]) -> Result<Option<(WebRequest, usize)>, NotHttp> {
    let Some((head, used)) = http1::decode_head(buf).map_err(|_| NotHttp)? else {
        return Ok(None);
    };
    let connection = |token: &str| {
        head.fields.iter().any(|(n, v)| {
            n == "connection" && v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token))
        })
    };
    let mut parts = head.start_line.split(' ');
    let (Some(method), Some(path), Some(version @ ("HTTP/1.1" | "HTTP/1.0")), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(NotHttp);
    };
    if method.is_empty() {
        return Err(NotHttp);
    }
    let close = connection("close") || (version == "HTTP/1.0" && !connection("keep-alive"));
    let request = WebRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        close,
    };
    Ok(Some((request, used)))
}

/// Parses an HTTP/3 request stream up to its `HEADERS`; like [`parse_http1`].
pub fn parse_h3(buf: &[u8]) -> Result<Option<(WebRequest, usize)>, NotHttp> {
    let Some((fields, used)) = h3::decode_headers(buf).map_err(|_| NotHttp)? else {
        return Ok(None);
    };
    let get = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    let (Some(method), Some(path)) = (get(":method"), get(":path")) else {
        return Err(NotHttp);
    };
    let request = WebRequest {
        method,
        path,
        close: false,
    };
    Ok(Some((request, used)))
}

/// HTTP/3 `HEADERS` frame for a response.
pub fn h3_response_headers(status: u16, fields: &[(&str, &str)]) -> Vec<u8> {
    h3::encode_response(status, fields).to_vec()
}

/// HTTP/3 `HEADERS` frame for a request (tests and probes).
pub fn h3_request_headers(method: &str, authority: &str, path: &str) -> Vec<u8> {
    h3::encode_method_request(method, authority, path).to_vec()
}

/// Decodes a response `HEADERS` frame: fields and bytes taken. For tests and probes.
pub fn decode_response_for_tests(buf: &[u8]) -> Option<(Vec<(String, String)>, usize)> {
    let (fields, used) = h3::decode_headers(buf).ok()??;
    Some((fields.0.clone(), used))
}

/// Opening bytes of a server's HTTP/3 control stream: `SETTINGS`, dynamic table off.
pub fn h3_server_control_stream() -> Vec<u8> {
    h3::client_control_stream()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_in_both_versions() {
        let wire = b"GET /index.html HTTP/1.1\r\nHost: a\r\n\r\nnext";
        let (req, used) = parse_http1(wire).unwrap().unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str(), used),
            ("GET", "/index.html", wire.len() - 4)
        );
        assert_eq!(parse_http1(b"GET / HT"), Ok(None));
        assert_eq!(parse_http1(b"\x16\x03\x01 binary\r\n\r\n"), Err(NotHttp));

        let frame = h3_request_headers("HEAD", "cdn.example.com", "/robots.txt");
        let (req, used) = parse_h3(&frame).unwrap().unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str(), used),
            ("HEAD", "/robots.txt", frame.len())
        );
    }
}

//! Device authentication: credentials, the connection URI, and the HTTP auth exchange that opens
//! every session (HTTP/3 on QUIC, HTTP/1.1 `Upgrade` on TCP+TLS).
//!
//! A rejected request gets no error: the server hands it to the masquerade site. The client
//! treats any answer other than success as [`HandshakeError::Rejected`].

pub(crate) mod encoding;
mod h3;
mod http1;
mod secret;
#[cfg(test)]
mod tests;
mod uri;

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::ops::{BitAnd, BitOr, Deref, RangeInclusive};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

pub use h3::{DataFrameError, DataFrameReader, client_control_stream, encode_data_frame};
pub use secret::{DeviceId, Token, TokenHash};
pub use uri::{ConnectionUri, Passthrough, TransportMode, UriError, format_pin};

/// Protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// Versions the server accepts.
pub const SUPPORTED_VERSIONS: RangeInclusive<u32> = 1..=1;
/// Deadline for the auth exchange after TLS completes.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const HEADER_AUTHORIZATION: &str = "authorization";
const HEADER_CLIENT: &str = "x-client";
const HEADER_SESSION: &str = "x-session";
/// Longest `plat` / `ver` value in `x-client`.
const MAX_LABEL: usize = 32;

/// Capability bits negotiated in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caps(pub u64);

impl Caps {
    /// Data right after `Connect`, before `ConnectResult`.
    pub const FAST_OPEN: Self = Self(1 << 0);
    /// UDP datagrams.
    pub const UDP: Self = Self(1 << 1);
    /// Padding in headers and the `Padding` control frame.
    pub const PADDING: Self = Self(1 << 2);
    /// Everything this build supports.
    pub const ALL: Self = Self(Self::FAST_OPEN.0 | Self::UDP.0 | Self::PADDING.0);

    /// True if every bit of `other` is set.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for Caps {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for Caps {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

/// Transport the auth exchange runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// HTTP/3 `POST` on the first bidi stream; success is `200`.
    Quic,
    /// HTTP/1.1 `GET` with `Upgrade`; success is `101`.
    Tls,
}

/// HTTP parsing failure inside the auth exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ParseError {
    #[error("truncated")]
    Truncated,
    #[error("over the size limit")]
    TooLarge,
    #[error("{0}")]
    Malformed(&'static str),
}

/// Decoded header fields in order, lowercase names. Holds the `authorization` value, so it is
/// wiped on drop.
pub(crate) struct Fields(pub(crate) Vec<(String, String)>);

impl Deref for Fields {
    type Target = [(String, String)];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Fields {
    fn drop(&mut self) {
        for (name, value) in &mut self.0 {
            name.zeroize();
            value.zeroize();
        }
    }
}

/// `x-client`: what the client is and offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// Protocol version.
    pub version: u32,
    /// Offered capabilities.
    pub caps: Caps,
    /// Platform label, e.g. `openwrt`.
    pub platform: String,
    /// Client build version.
    pub client_version: String,
}

impl ClientInfo {
    /// This build on `platform`.
    pub fn new(platform: &str, client_version: &str) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            caps: Caps::ALL,
            platform: platform.to_owned(),
            client_version: client_version.to_owned(),
        }
    }

    fn to_header(&self) -> String {
        format!(
            "v={}; caps={:x}; plat={}; ver={}",
            self.version, self.caps.0, self.platform, self.client_version
        )
    }

    fn parse(s: &str) -> Option<Self> {
        let p = params(s)?;
        let label = |key| {
            let value = param(&p, key).unwrap_or_default();
            is_label(value).then(|| value.to_owned())
        };
        Some(Self {
            version: parse_decimal(param(&p, "v")?)?,
            caps: Caps(parse_hex(param(&p, "caps")?)?),
            platform: label("plat")?,
            client_version: label("ver")?,
        })
    }
}

/// `x-session`: what the server granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    /// Protocol version in use.
    pub version: u32,
    /// Agreed capabilities: client offer ∩ server support.
    pub caps: Caps,
    /// Session id chosen by the server.
    pub sid: u64,
    /// Largest UDP datagram the server accepts.
    pub udp_max: u32,
}

impl SessionInfo {
    fn to_header(self) -> String {
        format!(
            "v={}; caps={:x}; sid={:x}; udp-max={}",
            self.version, self.caps.0, self.sid, self.udp_max
        )
    }

    fn parse(s: &str) -> Option<Self> {
        let p = params(s)?;
        Some(Self {
            version: parse_decimal(param(&p, "v")?)?,
            caps: Caps(parse_hex(param(&p, "caps")?)?),
            sid: parse_hex(param(&p, "sid")?)?,
            udp_max: parse_decimal(param(&p, "udp-max")?)?,
        })
    }
}

/// `k=v; k=v` with no empty or duplicate keys.
fn params(s: &str) -> Option<Vec<(&str, &str)>> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    for part in s.split(';') {
        let (k, v) = part.trim_matches(' ').split_once('=')?;
        if k.is_empty() || v.is_empty() || out.iter().any(|&(seen, _)| seen == k) {
            return None;
        }
        out.push((k, v));
    }
    Some(out)
}

fn param<'a>(params: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
    params.iter().find(|&&(k, _)| k == key).map(|&(_, v)| v)
}

/// Lowercase hex without leading `0x`, at most 16 digits.
fn parse_hex(s: &str) -> Option<u64> {
    let valid =
        (1..=16).contains(&s.len()) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    valid.then(|| u64::from_str_radix(s, 16).ok()).flatten()
}

fn parse_decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    let valid = (1..=10).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    valid.then(|| s.parse().ok()).flatten()
}

fn is_label(s: &str) -> bool {
    (1..=MAX_LABEL).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

fn authorization(id: &DeviceId, token: &Token) -> Zeroizing<String> {
    let token = token.to_base64url();
    // Sized up front so growing never leaves a copy of the token behind.
    let mut out = Zeroizing::new(String::with_capacity(8 + 32 + 1 + token.len()));
    let _ = write!(out, "Bearer {id}.{}", token.as_str());
    out
}

fn parse_authorization(s: &str) -> Option<(DeviceId, Token)> {
    let (id, token) = s.strip_prefix("Bearer ")?.split_once('.')?;
    Some((DeviceId::from_hex(id)?, Token::from_base64url(token)?))
}

/// Server-side record of a device.
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    /// SHA-256 of the device token.
    pub token_hash: TokenHash,
    /// Revoked devices are turned away.
    pub revoked: bool,
}

/// Device lookup for [`authenticate`].
pub trait DeviceRegistry {
    /// The device's record, if it exists.
    fn device(&self, id: &DeviceId) -> Option<&DeviceRecord>;
}

impl DeviceRegistry for HashMap<DeviceId, DeviceRecord> {
    fn device(&self, id: &DeviceId) -> Option<&DeviceRecord> {
        self.get(id)
    }
}

/// What the server offers to every device.
#[derive(Debug, Clone)]
pub struct ServerPolicy {
    /// Auth path; requests elsewhere go to the masquerade site.
    pub auth_path: String,
    /// Capabilities the server supports.
    pub caps: Caps,
    /// Largest UDP datagram the server accepts.
    pub udp_max: u32,
}

/// Why the server turned a request away. Never sent to the peer; for logs and metrics only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthFailure {
    /// Not a well-formed auth request (bad HTTP, missing or invalid headers).
    #[error("malformed request")]
    Malformed,
    /// Request for a path other than the auth path.
    #[error("wrong path")]
    WrongPath,
    /// No such device.
    #[error("unknown device")]
    UnknownDevice,
    /// Token does not match.
    #[error("bad token")]
    BadToken,
    /// Device is revoked.
    #[error("device revoked")]
    Revoked,
    /// Client protocol version is not supported.
    #[error("unsupported version")]
    UnsupportedVersion,
}

/// Auth request as received, before the credentials are checked.
#[derive(Clone)]
pub struct AuthRequest {
    /// Requested path.
    pub path: String,
    authorization: Zeroizing<String>,
    client: String,
}

impl fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRequest")
            .field("path", &self.path)
            .field("authorization", &"<redacted>")
            .field("client", &self.client)
            .finish()
    }
}

impl AuthRequest {
    /// Decodes the request from the front of the stream; returns it and bytes consumed, or
    /// `None` until it is complete. Anything that is not a well-formed request is
    /// [`AuthFailure::Malformed`] and goes to the masquerade site.
    pub fn decode(transport: Transport, buf: &[u8]) -> Result<Option<(Self, usize)>, AuthFailure> {
        let malformed = |_| AuthFailure::Malformed;
        let (path, fields, used) = match transport {
            Transport::Quic => {
                let Some((fields, used)) = h3::decode_headers(buf).map_err(malformed)? else {
                    return Ok(None);
                };
                let path = check_h3_request(&fields)?.to_owned();
                (path, fields, used)
            }
            Transport::Tls => {
                let Some((head, used)) = http1::decode_head(buf).map_err(malformed)? else {
                    return Ok(None);
                };
                let path = head.upgrade_path().map_err(malformed)?.to_owned();
                (path, head.fields, used)
            }
        };
        let request = Self {
            path,
            authorization: Zeroizing::new(single(&fields, HEADER_AUTHORIZATION)?.to_owned()),
            client: single(&fields, HEADER_CLIENT)?.to_owned(),
        };
        Ok(Some((request, used)))
    }
}

/// Pseudo-headers come first, each once; method `POST`, scheme `https`. Returns the path.
fn check_h3_request(fields: &[(String, String)]) -> Result<&str, AuthFailure> {
    let pseudo = fields
        .iter()
        .take_while(|(n, _)| n.starts_with(':'))
        .count();
    if fields[pseudo..].iter().any(|(n, _)| n.starts_with(':')) {
        return Err(AuthFailure::Malformed);
    }
    let pseudo = &fields[..pseudo];
    let get = |name| single(pseudo, name);
    if get(":method")? != "POST" || get(":scheme")? != "https" || pseudo.len() != 4 {
        return Err(AuthFailure::Malformed);
    }
    get(":authority")?;
    get(":path")
}

/// The value of a field that must appear exactly once.
fn single<'a>(fields: &'a [(String, String)], name: &str) -> Result<&'a str, AuthFailure> {
    let mut values = fields.iter().filter(|(n, _)| n == name);
    match (values.next(), values.next()) {
        (Some((_, v)), None) => Ok(v),
        _ => Err(AuthFailure::Malformed),
    }
}

/// A request that passed authentication.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// Authenticated device.
    pub device: DeviceId,
    /// What the client sent in `x-client`.
    pub client: ClientInfo,
    /// What to grant; send it with [`accept_response`].
    pub session: SessionInfo,
}

/// Checks a request against the registry. Every request with a well-formed bearer pays for
/// hashing and a constant-time compare, against a dummy hash when the device is unknown, before
/// anything else is decided, so neither the device nor the path shows in the timing.
pub fn authenticate(
    request: &AuthRequest,
    registry: &impl DeviceRegistry,
    policy: &ServerPolicy,
    sid: u64,
) -> Result<Accepted, AuthFailure> {
    let (device, token) =
        parse_authorization(&request.authorization).ok_or(AuthFailure::Malformed)?;
    let record = registry.device(&device);
    let stored = record.map_or(TokenHash::DUMMY, |r| r.token_hash);
    let token_ok = stored.matches(&token.hash());
    // Parsed before the path check too, so a wrong path skips no work.
    let client = ClientInfo::parse(&request.client);
    if request.path != policy.auth_path {
        return Err(AuthFailure::WrongPath);
    }
    let client = client.ok_or(AuthFailure::Malformed)?;
    let record = record.ok_or(AuthFailure::UnknownDevice)?;
    if !token_ok {
        return Err(AuthFailure::BadToken);
    }
    if record.revoked {
        return Err(AuthFailure::Revoked);
    }
    if !SUPPORTED_VERSIONS.contains(&client.version) {
        return Err(AuthFailure::UnsupportedVersion);
    }
    let session = SessionInfo {
        version: client.version,
        caps: client.caps & policy.caps,
        sid,
        udp_max: policy.udp_max,
    };
    Ok(Accepted {
        device,
        client,
        session,
    })
}

/// Success response carrying `x-session`: `200` on QUIC, `101` on TCP+TLS.
pub fn accept_response(transport: Transport, session: &SessionInfo) -> Vec<u8> {
    let header = session.to_header();
    let fields = [(HEADER_SESSION, header.as_str())];
    match transport {
        Transport::Quic => h3::encode_response(200, &fields).to_vec(),
        Transport::Tls => http1::encode_switching_protocols(&fields),
    }
}

/// Plain `404 Not Found` for a rejected request; stands in until the masquerade site answers
/// instead.
pub fn not_found_response(transport: Transport) -> Vec<u8> {
    match transport {
        Transport::Quic => h3::encode_response(404, &[("content-length", "0")]).to_vec(),
        Transport::Tls => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec(),
    }
}

/// Client handshake failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// Server answered with something other than success: bad credentials or not our server.
    #[error("authentication rejected")]
    Rejected,
    /// Success status, but the response or its `x-session` is invalid.
    #[error("malformed auth response")]
    Malformed,
    /// No answer within [`HANDSHAKE_TIMEOUT`].
    #[error("auth timed out")]
    Timeout,
    /// The URI or client info would produce an invalid request (bad path, authority or label).
    #[error("invalid auth request parameters")]
    InvalidInput,
    /// Input after the handshake already established; it belongs to the session.
    #[error("handshake already finished")]
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Established,
    Failed(HandshakeError),
}

/// Handshake result: the session and any bytes that followed the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Established {
    /// What the server granted.
    pub session: SessionInfo,
    /// Bytes after the response: control channel in HTTP/3 `DATA` frames (QUIC) or mux
    /// (TCP+TLS).
    pub leftover: Vec<u8>,
}

/// Client side of the auth exchange, sans-io: send [`ClientHandshake::start`]'s bytes, feed the
/// response to [`ClientHandshake::handle_input`] and call [`ClientHandshake::handle_timeout`]
/// at [`ClientHandshake::deadline`].
#[derive(Debug)]
pub struct ClientHandshake {
    transport: Transport,
    offered: Caps,
    buf: Vec<u8>,
    deadline: Instant,
    state: State,
}

impl ClientHandshake {
    /// Starts the exchange; returns the state and the request to send. On QUIC the request goes
    /// on the first bidi stream, after [`client_control_stream`] is opened.
    pub fn start(
        transport: Transport,
        uri: &ConnectionUri,
        info: &ClientInfo,
        now: Instant,
    ) -> Result<(Self, Zeroizing<Vec<u8>>), HandshakeError> {
        // Public fields can be set by hand, so check what goes into the request line and headers.
        let visible = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic());
        let authority = uri.authority();
        if !(uri.path.starts_with('/') && visible(&uri.path) && visible(&authority))
            || !is_label(&info.platform)
            || !is_label(&info.client_version)
        {
            return Err(HandshakeError::InvalidInput);
        }
        let auth = authorization(&uri.device_id, &uri.token);
        let client = info.to_header();
        let fields = [
            (HEADER_AUTHORIZATION, auth.as_str()),
            (HEADER_CLIENT, client.as_str()),
        ];
        let request = match transport {
            Transport::Quic => h3::encode_request(&authority, &uri.path, &fields),
            Transport::Tls => http1::encode_request(&authority, &uri.path, &fields),
        };
        let state = Self {
            transport,
            offered: info.caps,
            buf: Vec::new(),
            deadline: now + HANDSHAKE_TIMEOUT,
            state: State::Pending,
        };
        Ok((state, request))
    }

    /// When [`ClientHandshake::handle_timeout`] must be called.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Feeds response bytes; returns the session once the response is complete. After a
    /// failure every call returns the same error.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<Option<Established>, HandshakeError> {
        match self.state {
            State::Pending => {}
            State::Established => return Err(HandshakeError::Finished),
            State::Failed(e) => return Err(e),
        }
        let result = self.process(data);
        match &result {
            Ok(Some(_)) => self.state = State::Established,
            Err(e) => self.state = State::Failed(*e),
            Ok(None) => {}
        }
        result
    }

    fn process(&mut self, data: &[u8]) -> Result<Option<Established>, HandshakeError> {
        self.buf.extend_from_slice(data);
        let malformed = |_| HandshakeError::Malformed;
        let (status, fields, used) = match self.transport {
            Transport::Quic => {
                let Some((fields, used)) = h3::decode_headers(&self.buf).map_err(malformed)? else {
                    return Ok(None);
                };
                let status = single(&fields, ":status")
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok());
                (status, fields, used)
            }
            Transport::Tls => {
                let Some((head, used)) = http1::decode_head(&self.buf).map_err(malformed)? else {
                    return Ok(None);
                };
                if head.status() == Some(101) && !head.is_upgrade() {
                    return Err(HandshakeError::Malformed);
                }
                (head.status(), head.fields, used)
            }
        };
        let success = match self.transport {
            Transport::Quic => 200,
            Transport::Tls => 101,
        };
        if status != Some(success) {
            return Err(HandshakeError::Rejected);
        }
        let session = single(&fields, HEADER_SESSION)
            .ok()
            .and_then(SessionInfo::parse)
            .filter(|s| SUPPORTED_VERSIONS.contains(&s.version) && self.offered.contains(s.caps))
            .ok_or(HandshakeError::Malformed)?;
        let leftover = self.buf.split_off(used);
        self.buf = Vec::new();
        Ok(Some(Established { session, leftover }))
    }

    /// Fails the handshake once the deadline has passed without a response.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), HandshakeError> {
        if self.state == State::Pending && now >= self.deadline {
            self.state = State::Failed(HandshakeError::Timeout);
            return Err(HandshakeError::Timeout);
        }
        Ok(())
    }
}

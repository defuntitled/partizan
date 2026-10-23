//! Codec errors.

/// Failure to decode a frame from received bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The buffer ends before the frame does; retry once more bytes arrive.
    #[error("input is incomplete")]
    Incomplete,
    /// A varint uses more bytes than its value needs.
    #[error("varint is not minimally encoded")]
    NonMinimalVarint,
    /// The frame type differs from the one expected at this point.
    #[error("unexpected frame type {0:#x}")]
    UnexpectedType(u64),
    /// Address type is not IPv4, domain or IPv6.
    #[error("unknown address type {0:#x}")]
    UnknownAddrType(u8),
    /// Domain name is empty or not UTF-8.
    #[error("domain name is empty or not UTF-8")]
    InvalidDomain,
    /// `ConnectResult` status is outside the known range.
    #[error("unknown connect status {0:#x}")]
    UnknownStatus(u8),
    /// A declared length exceeds its protocol limit.
    #[error("declared length {0} exceeds the limit")]
    LengthLimit(u64),
    /// A complete datagram ends before its header does.
    #[error("datagram is truncated")]
    Truncated,
    /// Control frame type below the extension range (0x40) is not known.
    #[error("unknown control frame type {0:#x}")]
    UnknownControlType(u64),
    /// Body of a known control frame type does not take exactly `length` bytes.
    #[error("control frame {0:#x} has a malformed body")]
    MalformedBody(u64),
    /// Reserved bits are set in `UdpDatagram` flags.
    #[error("reserved flag bits set: {0:#04x}")]
    ReservedFlags(u8),
}

impl DecodeError {
    /// Code to close the connection with, or `None` for [`DecodeError::Incomplete`], which only
    /// means more bytes are needed.
    ///
    /// Not for [`UdpDatagram`](crate::UdpDatagram) errors: a malformed datagram is dropped and
    /// counted, the connection stays up.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Incomplete => None,
            _ => Some(ErrorCode::PROTOCOL_ERROR),
        }
    }
}

/// Failure to encode a frame; nothing is written to the output when it is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// Value is above the varint maximum of 2^62 − 1.
    #[error("value {0} does not fit in a varint")]
    VarintOverflow(u64),
    /// Domain name length is not in 1..=255 bytes.
    #[error("domain name length {0} is not in 1..=255")]
    InvalidDomainLength(usize),
    /// Padding is longer than its limit: [`MAX_PADDING`](crate::connect::MAX_PADDING) in
    /// headers, [`MAX_CONTROL_BODY`](crate::control::MAX_CONTROL_BODY) in a `Padding` frame.
    #[error("padding length {0} exceeds the limit")]
    PaddingLimit(usize),
}

/// Application error code for `CONNECTION_CLOSE` / `RESET_STREAM`, mux `RST` and `GoAway`.
///
/// Kept open (not an enum) so codes from newer peers still decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u64);

impl ErrorCode {
    /// No error.
    pub const NO_ERROR: Self = Self(0x00);
    /// Peer violated the protocol; client logs and reconnects.
    pub const PROTOCOL_ERROR: Self = Self(0x01);
    /// Device revoked; client stops without retrying.
    pub const REVOKED: Self = Self(0x02);
    /// Too many sessions for the device; client retries with backoff.
    pub const SESSION_LIMIT: Self = Self(0x03);
    /// Server is shutting down; client retries after `retry_after_ms`.
    pub const SERVER_SHUTDOWN: Self = Self(0x04);
    /// Session idle; client reconnects silently on demand.
    pub const IDLE_TIMEOUT: Self = Self(0x05);
    /// Stream: target unreachable (SOCKS5 REP 0x04).
    pub const TARGET_UNREACHABLE: Self = Self(0x10);
    /// Stream: target refused the connection (SOCKS5 REP 0x05).
    pub const TARGET_REFUSED: Self = Self(0x11);
    /// Stream: connect to the target timed out (SOCKS5 REP 0x06).
    pub const TARGET_TIMEOUT: Self = Self(0x12);
    /// Stream: denied by the egress policy (SOCKS5 REP 0x02).
    pub const NOT_ALLOWED: Self = Self(0x13);
}

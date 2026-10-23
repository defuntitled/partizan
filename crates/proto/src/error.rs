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
    /// Padding is longer than [`MAX_PADDING`](crate::connect::MAX_PADDING).
    #[error("padding length {0} exceeds the limit")]
    PaddingLimit(usize),
}

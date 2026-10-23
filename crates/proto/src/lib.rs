//! Sans-io protocol core: frames, varint, codecs, session state machine, auth and mux.
//!
//! Independent of the OS, the async runtime and the clock (time is passed in), so it
//! builds unchanged for mobile wrappers.

#![forbid(unsafe_code)]

pub mod addr;
pub mod connect;
mod error;
mod reader;
pub mod varint;

pub use addr::{Host, TargetAddr};
pub use connect::{Connect, ConnectResult, ConnectStatus};
pub use error::{DecodeError, EncodeError};

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

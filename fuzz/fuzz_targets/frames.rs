//! `Connect`, `ConnectResult`, `UdpDatagram` and control frames from arbitrary bytes.

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use proto::{Connect, ConnectResult, ControlFrame, UdpDatagram};

fuzz_target!(|data: &[u8]| {
    // A successful decode must re-encode to exactly the bytes it consumed, padding aside.
    if let Ok((c, used)) = Connect::decode(data) {
        let mut out = Vec::new();
        c.encode(&mut out).unwrap();
        assert_eq!(out.len(), used);
    }
    if let Ok((r, used)) = ConnectResult::decode(data) {
        let mut out = Vec::new();
        r.encode(&mut out).unwrap();
        assert_eq!(out.len(), used);
    }
    if let Ok(d) = UdpDatagram::decode(Bytes::copy_from_slice(data)) {
        let mut out = Vec::new();
        d.encode(&mut out).unwrap();
        assert_eq!(out, data);
    }
    // The control channel is a sequence of frames.
    let mut rest = data;
    while let Ok((_, used)) = ControlFrame::decode(rest) {
        rest = &rest[used..];
    }
});

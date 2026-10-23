//! Control channel frames: `type: varint, length: varint, body`.
//!
//! Types from 0x40 up are extensions and are skipped by `length` when unknown; an unknown type
//! below 0x40 is a protocol error.

use bytes::BufMut;

use crate::reader::Reader;
use crate::{DecodeError, EncodeError, ErrorCode, varint};

/// Largest allowed `length`; bigger values are rejected before waiting for the body.
pub const MAX_CONTROL_BODY: usize = 16 * 1024;

/// First type of the extension range.
pub const EXTENSION_TYPES: u64 = 0x40;

const TYPE_PING: u64 = 0x10;
const TYPE_PONG: u64 = 0x11;
const TYPE_UDP_CLOSE: u64 = 0x12;
const TYPE_GO_AWAY: u64 = 0x13;
const TYPE_PADDING: u64 = 0x14;

/// Frame on the control channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFrame {
    /// RTT probe (and keepalive over TCP+TLS); answered with `Pong` carrying the same nonce.
    Ping {
        /// Echoed back in `Pong`.
        nonce: u64,
    },
    /// Answer to `Ping`.
    Pong {
        /// Nonce from the `Ping`.
        nonce: u64,
    },
    /// Closes a UDP session.
    UdpClose {
        /// UDP session to close.
        session_id: u64,
        /// Close reason.
        reason: u8,
    },
    /// Server → client: the session is ending.
    GoAway {
        /// Why the session ends.
        code: ErrorCode,
        /// Delay before reconnecting, in milliseconds.
        retry_after_ms: u64,
    },
    /// Traffic shaping; zeros on encode, contents ignored on decode.
    Padding {
        /// Number of padding bytes.
        len: usize,
    },
}

impl ControlFrame {
    fn type_code(&self) -> u64 {
        match self {
            Self::Ping { .. } => TYPE_PING,
            Self::Pong { .. } => TYPE_PONG,
            Self::UdpClose { .. } => TYPE_UDP_CLOSE,
            Self::GoAway { .. } => TYPE_GO_AWAY,
            Self::Padding { .. } => TYPE_PADDING,
        }
    }

    /// Validates the frame and returns its body length.
    fn body_len(&self) -> Result<usize, EncodeError> {
        Ok(match self {
            Self::Ping { .. } | Self::Pong { .. } => 8,
            Self::UdpClose { session_id, .. } => varint::encoded_len(*session_id)? + 1,
            Self::GoAway {
                code,
                retry_after_ms,
            } => varint::encoded_len(code.0)? + varint::encoded_len(*retry_after_ms)?,
            Self::Padding { len } if *len > MAX_CONTROL_BODY => {
                return Err(EncodeError::PaddingLimit(*len));
            }
            Self::Padding { len } => *len,
        })
    }

    /// Appends the encoded frame; writes nothing on error.
    pub fn encode(&self, out: &mut impl BufMut) -> Result<(), EncodeError> {
        let len = self.body_len()?;
        varint::encode(self.type_code(), out)?;
        varint::encode(len as u64, out)?;
        match self {
            Self::Ping { nonce } | Self::Pong { nonce } => out.put_u64(*nonce),
            Self::UdpClose { session_id, reason } => {
                varint::encode(*session_id, out)?;
                out.put_u8(*reason);
            }
            Self::GoAway {
                code,
                retry_after_ms,
            } => {
                varint::encode(code.0, out)?;
                varint::encode(*retry_after_ms, out)?;
            }
            Self::Padding { len } => out.put_bytes(0, *len),
        }
        Ok(())
    }

    /// Decodes a frame from the front of `buf`, returning it and the bytes consumed.
    ///
    /// An unknown extension frame is skipped: the result is `None` with its full length consumed.
    pub fn decode(buf: &[u8]) -> Result<(Option<Self>, usize), DecodeError> {
        let mut r = Reader::new(buf);
        let ty = r.varint()?;
        let known = is_known(ty);
        if !known && ty < EXTENSION_TYPES {
            return Err(DecodeError::UnknownControlType(ty));
        }
        let len = r.varint()?;
        if len > MAX_CONTROL_BODY as u64 {
            return Err(DecodeError::LengthLimit(len));
        }
        let body = r.bytes(len as usize)?;
        let frame = if known {
            Some(Self::decode_body(ty, body)?)
        } else {
            None
        };
        Ok((frame, r.position()))
    }

    fn decode_body(ty: u64, body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        let parse = |r: &mut Reader<'_>| -> Result<Self, DecodeError> {
            Ok(match ty {
                TYPE_PING => Self::Ping { nonce: r.u64_be()? },
                TYPE_PONG => Self::Pong { nonce: r.u64_be()? },
                TYPE_UDP_CLOSE => Self::UdpClose {
                    session_id: r.varint()?,
                    reason: r.u8()?,
                },
                TYPE_GO_AWAY => Self::GoAway {
                    code: ErrorCode(r.varint()?),
                    retry_after_ms: r.varint()?,
                },
                TYPE_PADDING => {
                    r.bytes(body.len())?;
                    Self::Padding { len: body.len() }
                }
                _ => return Err(DecodeError::UnknownControlType(ty)),
            })
        };
        let frame = parse(&mut r).map_err(|e| match e {
            // The body is already complete: running short means it is malformed.
            DecodeError::Incomplete => DecodeError::MalformedBody(ty),
            e => e,
        })?;
        if !r.is_empty() {
            return Err(DecodeError::MalformedBody(ty));
        }
        Ok(frame)
    }
}

/// Types `decode_body` parses; must list every arm there.
fn is_known(ty: u64) -> bool {
    matches!(
        ty,
        TYPE_PING | TYPE_PONG | TYPE_UDP_CLOSE | TYPE_GO_AWAY | TYPE_PADDING
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: &ControlFrame) -> Vec<u8> {
        let mut out = Vec::new();
        f.encode(&mut out).unwrap();
        out
    }

    fn samples() -> Vec<ControlFrame> {
        vec![
            ControlFrame::Ping { nonce: 0 },
            ControlFrame::Pong { nonce: u64::MAX },
            ControlFrame::UdpClose {
                session_id: 70_000,
                reason: 1,
            },
            ControlFrame::GoAway {
                code: ErrorCode::REVOKED,
                retry_after_ms: 0,
            },
            ControlFrame::GoAway {
                code: ErrorCode(varint::MAX),
                retry_after_ms: varint::MAX,
            },
            ControlFrame::Padding { len: 0 },
            ControlFrame::Padding {
                len: MAX_CONTROL_BODY,
            },
        ]
    }

    #[test]
    fn c03_t2_control_frames_roundtrip() {
        for f in samples() {
            let bytes = enc(&f);
            assert_eq!(ControlFrame::decode(&bytes), Ok((Some(f), bytes.len())));
        }
        // Ping nonce is a fixed 8-byte big-endian u64.
        assert_eq!(
            enc(&ControlFrame::Ping { nonce: 0x0102 }),
            [0x10, 0x08, 0, 0, 0, 0, 0, 0, 0x01, 0x02]
        );
    }

    #[test]
    fn c03_t3_unknown_extension_type_is_skipped_by_length() {
        // Type 0x40 (two-byte varint), 3-byte body, then a Ping.
        let mut bytes = vec![0x40, 0x40, 0x03, b'a', b'b', b'c'];
        bytes.extend(enc(&ControlFrame::Ping { nonce: 7 }));
        assert_eq!(ControlFrame::decode(&bytes), Ok((None, 6)));
        assert_eq!(
            ControlFrame::decode(&bytes[6..]),
            Ok((Some(ControlFrame::Ping { nonce: 7 }), 10))
        );
        // Largest type, empty body.
        let mut bytes = Vec::new();
        varint::encode(varint::MAX, &mut bytes).unwrap();
        bytes.push(0x00);
        assert_eq!(ControlFrame::decode(&bytes), Ok((None, 9)));
        // Skipping still waits for the whole body.
        assert_eq!(
            ControlFrame::decode(&[0x40, 0x40, 0x03, b'a']),
            Err(DecodeError::Incomplete)
        );
    }

    #[test]
    fn c03_t4_unknown_type_below_0x40_is_protocol_error() {
        for ty in [0x00, 0x01, 0x0f, 0x15, 0x3f] {
            // Rejected from the type alone, without waiting for length or body.
            let err = ControlFrame::decode(&[ty]).unwrap_err();
            assert_eq!(err, DecodeError::UnknownControlType(ty.into()));
            assert_eq!(err.code(), Some(ErrorCode::PROTOCOL_ERROR));
        }
    }

    #[test]
    fn c03_t5_go_away_carries_code_and_retry_after() {
        let f = ControlFrame::GoAway {
            code: ErrorCode::SERVER_SHUTDOWN,
            retry_after_ms: 1500,
        };
        // 1500 = 0x5dc, a two-byte varint.
        assert_eq!(enc(&f), [0x13, 0x03, 0x04, 0x45, 0xdc]);
        assert_eq!(ControlFrame::decode(&enc(&f)), Ok((Some(f), 5)));
    }

    #[test]
    fn truncated_control_frame_is_incomplete() {
        for f in samples() {
            let bytes = enc(&f);
            for cut in 0..bytes.len() {
                assert_eq!(
                    ControlFrame::decode(&bytes[..cut]),
                    Err(DecodeError::Incomplete),
                    "{f:?} cut at {cut}"
                );
            }
        }
    }

    #[test]
    fn malformed_control_frame_is_rejected() {
        let cases: [(&[u8], DecodeError); 5] = [
            // Ping body shorter and longer than 8 bytes.
            (
                &[0x10, 0x07, 0, 0, 0, 0, 0, 0, 0],
                DecodeError::MalformedBody(0x10),
            ),
            (
                &[0x11, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                DecodeError::MalformedBody(0x11),
            ),
            // GoAway missing retry_after_ms; UdpClose with a trailing byte.
            (&[0x13, 0x01, 0x04], DecodeError::MalformedBody(0x13)),
            (
                &[0x12, 0x03, 0x01, 0x00, 0xff],
                DecodeError::MalformedBody(0x12),
            ),
            // length = 16385, rejected before the body arrives.
            (
                &[0x14, 0x80, 0x00, 0x40, 0x01],
                DecodeError::LengthLimit(16_385),
            ),
        ];
        for (bytes, err) in cases {
            assert_eq!(ControlFrame::decode(bytes), Err(err), "{bytes:02x?}");
            assert_eq!(err.code(), Some(ErrorCode::PROTOCOL_ERROR));
        }
        let mut out = Vec::new();
        let f = ControlFrame::Padding {
            len: MAX_CONTROL_BODY + 1,
        };
        assert_eq!(
            f.encode(&mut out),
            Err(EncodeError::PaddingLimit(MAX_CONTROL_BODY + 1))
        );
        let f = ControlFrame::UdpClose {
            session_id: varint::MAX + 1,
            reason: 0,
        };
        assert_eq!(
            f.encode(&mut out),
            Err(EncodeError::VarintOverflow(varint::MAX + 1))
        );
        assert!(out.is_empty());
    }

    #[test]
    fn c03_t5_unknown_code_from_newer_peer_roundtrips() {
        let f = ControlFrame::GoAway {
            code: ErrorCode(0x99),
            retry_after_ms: 0,
        };
        assert_eq!(ControlFrame::decode(&enc(&f)), Ok((Some(f), 5)));
    }

    #[test]
    fn udp_close_wire_format() {
        // session_id 300 = 0x412c (two-byte varint), reason 1.
        let f = ControlFrame::UdpClose {
            session_id: 300,
            reason: 1,
        };
        assert_eq!(enc(&f), [0x12, 0x03, 0x41, 0x2c, 0x01]);
    }

    #[test]
    fn extension_and_type_edge_cases() {
        // Extension frame over the length limit is rejected, not skipped.
        assert_eq!(
            ControlFrame::decode(&[0x40, 0x40, 0x80, 0x00, 0x40, 0x01]),
            Err(DecodeError::LengthLimit(16_385))
        );
        // Ping type 0x10 encoded in two bytes.
        assert_eq!(
            ControlFrame::decode(&[0x40, 0x10, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::NonMinimalVarint)
        );
    }
}

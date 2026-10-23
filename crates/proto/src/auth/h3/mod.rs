//! Just enough HTTP/3 (RFC 9114) for the auth exchange on the first bidi stream.
//!
//! The request is `POST <auth_path>` without a body and without FIN. After the response
//! `HEADERS` the control channel runs inside `DATA` frames on the same stream, so a server built
//! on a regular HTTP/3 stack keeps a valid stream.

mod qpack;
mod tables;

use zeroize::Zeroizing;

use crate::auth::{Fields, ParseError};
use crate::varint;

const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;
const STREAM_CONTROL: u64 = 0x00;
/// Most bytes we buffer on the auth stream before `HEADERS` is complete, skipped frames
/// included.
const MAX_HEAD: usize = 16 * 1024;

/// Opening bytes of the client's HTTP/3 control stream (unidirectional): an empty `SETTINGS`,
/// so QPACK dynamic table capacity stays 0.
pub fn client_control_stream() -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(STREAM_CONTROL, &mut out);
    frame(FRAME_SETTINGS, &[], &mut out);
    out
}

pub(crate) fn encode_request(
    authority: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> Zeroizing<Vec<u8>> {
    let mut fields = vec![
        (":method", "POST"),
        (":authority", authority),
        (":scheme", "https"),
        (":path", path),
    ];
    fields.extend_from_slice(extra);
    headers_frame(&fields)
}

pub(crate) fn encode_method_request(
    method: &str,
    authority: &str,
    path: &str,
) -> Zeroizing<Vec<u8>> {
    headers_frame(&[
        (":method", method),
        (":authority", authority),
        (":scheme", "https"),
        (":path", path),
    ])
}

pub(crate) fn encode_response(status: u16, extra: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    let status = status.to_string();
    let mut fields = vec![(":status", status.as_str())];
    fields.extend_from_slice(extra);
    headers_frame(&fields)
}

/// `HEADERS` frame built in buffers sized up front, so no unzeroized copy of a field is left
/// behind by reallocation.
fn headers_frame(fields: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    let bound = qpack::encoded_len_bound(fields);
    let mut block = Zeroizing::new(Vec::with_capacity(bound));
    qpack::encode(fields, &mut block);
    debug_assert!(block.len() <= bound, "QPACK size bound too small");
    let mut out = Zeroizing::new(Vec::with_capacity(block.len() + 16));
    frame(FRAME_HEADERS, &block, &mut out);
    out
}

/// Reads frames until the first `HEADERS` and decodes it; returns the fields and bytes consumed,
/// or `None` until the frame is complete. Unknown and reserved frame types are skipped, but all
/// of it must fit in [`MAX_HEAD`] bytes.
pub(crate) fn decode_headers(buf: &[u8]) -> Result<Option<(Fields, usize)>, ParseError> {
    let mut pos = 0;
    loop {
        let mut header = pos;
        let (Some(ty), Some(len)) = (read_varint(buf, &mut header), read_varint(buf, &mut header))
        else {
            return if buf.len() >= MAX_HEAD {
                Err(ParseError::TooLarge)
            } else {
                Ok(None)
            };
        };
        let end = usize::try_from(len)
            .ok()
            .and_then(|len| header.checked_add(len))
            .filter(|&end| end <= MAX_HEAD)
            .ok_or(ParseError::TooLarge)?;
        let Some(payload) = buf.get(header..end) else {
            return Ok(None);
        };
        pos = end;
        match ty {
            FRAME_HEADERS => return Ok(Some((qpack::decode(payload)?, pos))),
            // DATA before HEADERS and frames that belong on the control stream are errors here
            // (RFC 9114 §7.2): SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, PUSH_PROMISE.
            FRAME_DATA | FRAME_SETTINGS | 0x03 | 0x05 | 0x07 | 0x0d => {
                return Err(ParseError::Malformed("unexpected HTTP/3 frame"));
            }
            // HTTP/2-only frame types are reserved and also errors.
            0x02 | 0x06 | 0x08 | 0x09 => {
                return Err(ParseError::Malformed("reserved HTTP/3 frame"));
            }
            _ => {}
        }
    }
}

/// Wraps control-channel bytes in an HTTP/3 `DATA` frame.
pub fn encode_data_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    frame(FRAME_DATA, payload, &mut out);
    out
}

/// Largest `DATA` frame accepted on the control stream.
const MAX_DATA_FRAME: usize = 64 * 1024;

/// Unwraps the control channel from the HTTP/3 `DATA` frames that follow the response
/// `HEADERS`. Unknown frame types are skipped; anything else is an error.
#[derive(Debug, Default)]
pub struct DataFrameReader {
    buf: Vec<u8>,
}

impl DataFrameReader {
    /// Feeds stream bytes; returns the payload of every `DATA` frame completed by them.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, DataFrameError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut pos = 0;
        loop {
            let mut header = pos;
            let (Some(ty), Some(len)) = (
                read_varint(&self.buf, &mut header),
                read_varint(&self.buf, &mut header),
            ) else {
                break;
            };
            let len = usize::try_from(len)
                .ok()
                .filter(|&len| len <= MAX_DATA_FRAME)
                .ok_or(DataFrameError)?;
            let Some(payload) = self.buf.get(header..header + len) else {
                break;
            };
            match ty {
                FRAME_DATA => out.extend_from_slice(payload),
                FRAME_HEADERS | FRAME_SETTINGS | 0x02..=0x09 | 0x0d => return Err(DataFrameError),
                _ => {}
            }
            pos = header + len;
        }
        self.buf.drain(..pos);
        Ok(out)
    }
}

/// The control stream carried something other than `DATA` frames, or an oversized one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("bad HTTP/3 framing on the control stream")]
pub struct DataFrameError;

/// QUIC varint as RFC 9000 allows it, non-minimal encodings included: unlike our own frames,
/// HTTP/3 comes from third-party stacks. `None` means more bytes are needed.
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1 << (first >> 6);
    let bytes = buf.get(*pos..*pos + len)?;
    *pos += len;
    Some(
        bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |acc, &b| acc << 8 | u64::from(b)),
    )
}

fn frame(ty: u64, payload: &[u8], out: &mut Vec<u8>) {
    put_varint(ty, out);
    put_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn put_varint(value: u64, out: &mut Vec<u8>) {
    varint::encode(value.min(varint::MAX), out).expect("value clamped to the varint range");
}

#[cfg(test)]
pub(crate) use qpack::huffman_encode;

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(fields: &[(&str, &str)]) -> Vec<(String, String)> {
        fields
            .iter()
            .map(|&(n, v)| (n.to_owned(), v.to_owned()))
            .collect()
    }

    #[test]
    fn request_roundtrips_and_stream_continues_after_it() {
        let mut wire =
            encode_request("cdn.example.com", "/api/v2/sync", &[("x-client", "v=1")]).to_vec();
        let len = wire.len();
        wire.extend_from_slice(b"control bytes");
        let (fields, used) = decode_headers(&wire).unwrap().unwrap();
        assert_eq!(used, len);
        assert_eq!(
            fields.0,
            owned(&[
                (":method", "POST"),
                (":authority", "cdn.example.com"),
                (":scheme", "https"),
                (":path", "/api/v2/sync"),
                ("x-client", "v=1"),
            ])
        );
        for cut in 0..len {
            assert_eq!(
                decode_headers(&wire[..cut]).map(|r| r.is_none()),
                Ok(true),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn unknown_frames_are_skipped_and_forbidden_ones_rejected() {
        // Reserved grease type 0x21, non-minimally encoded (allowed in HTTP/3), then the response.
        let mut wire = vec![0x40, 0x21, 0x02, 0xaa, 0xbb];
        wire.extend_from_slice(&encode_response(200, &[]));
        let (fields, used) = decode_headers(&wire).unwrap().unwrap();
        assert_eq!(fields.0, owned(&[(":status", "200")]));
        assert_eq!(used, wire.len());

        for ty in [FRAME_DATA, FRAME_SETTINGS, 0x07, 0x02] {
            let mut wire = Vec::new();
            frame(ty, &[], &mut wire);
            assert!(decode_headers(&wire).is_err(), "type {ty:#x}");
        }
        let mut huge = Vec::new();
        put_varint(FRAME_HEADERS, &mut huge);
        put_varint(MAX_HEAD as u64 + 1, &mut huge);
        assert_eq!(decode_headers(&huge).err(), Some(ParseError::TooLarge));
    }

    #[test]
    fn grease_before_headers_is_bounded_in_total() {
        // Many small skipped frames add up to the limit, so a prober cannot stall us forever.
        let mut wire = Vec::new();
        while wire.len() < MAX_HEAD + 64 {
            frame(0x21, &[0; 100], &mut wire);
        }
        assert_eq!(decode_headers(&wire).err(), Some(ParseError::TooLarge));
        // Bytes that never form a frame header also stop at the limit.
        assert_eq!(
            decode_headers(&[0xff; MAX_HEAD]).err(),
            Some(ParseError::TooLarge)
        );
    }

    #[test]
    fn data_frames_unwrap_across_reads() {
        let mut wire = encode_data_frame(b"ping");
        wire.extend_from_slice(&[0x21, 0x01, 0xaa]); // Grease frame, skipped.
        wire.extend(encode_data_frame(b"pong"));
        let mut reader = DataFrameReader::default();
        let mut got = Vec::new();
        for byte in &wire {
            got.extend(reader.push(&[*byte]).unwrap());
        }
        assert_eq!(got, b"pingpong");
        assert_eq!(
            DataFrameReader::default().push(&encode_response(200, &[])),
            Err(DataFrameError)
        );
        let mut huge = Vec::new();
        put_varint(FRAME_DATA, &mut huge);
        put_varint(MAX_DATA_FRAME as u64 + 1, &mut huge);
        assert_eq!(DataFrameReader::default().push(&huge), Err(DataFrameError));
    }

    #[test]
    fn control_stream_opens_with_empty_settings() {
        assert_eq!(client_control_stream(), [0x00, 0x04, 0x00]);
    }
}

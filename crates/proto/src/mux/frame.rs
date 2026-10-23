//! `MuxFrame` header: `stream_id: varint, type: u8, length: varint`, then `length` bytes.

use bytes::BufMut;

use super::{MAX_CONTROL, MAX_DATA, MAX_DATAGRAM, MuxError};
use crate::reader::Reader;
use crate::{DecodeError, varint};

/// Frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FrameType {
    Data = 0x0,
    Open = 0x1,
    Fin = 0x2,
    Rst = 0x3,
    WindowUpdate = 0x4,
    Datagram = 0x5,
    Control = 0x6,
}

impl FrameType {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x0 => Self::Data,
            0x1 => Self::Open,
            0x2 => Self::Fin,
            0x3 => Self::Rst,
            0x4 => Self::WindowUpdate,
            0x5 => Self::Datagram,
            0x6 => Self::Control,
            _ => return None,
        })
    }

    fn max_payload(self) -> usize {
        match self {
            Self::Data | Self::Open => MAX_DATA,
            Self::Fin => 0,
            Self::Rst | Self::WindowUpdate => 8,
            Self::Datagram => MAX_DATAGRAM,
            Self::Control => MAX_CONTROL,
        }
    }
}

/// Decoded frame header; `len` is already checked against the type's limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) stream_id: u64,
    pub(crate) ty: FrameType,
    pub(crate) len: usize,
}

/// Decodes a header from the front of `buf`; `None` means more bytes are needed.
pub(crate) fn decode(buf: &[u8]) -> Result<Option<(Header, usize)>, MuxError> {
    let mut r = Reader::new(buf);
    let header = (|| {
        let stream_id = r.varint()?;
        let ty = r.u8()?;
        let ty = FrameType::from_u8(ty).ok_or(MuxError::Protocol("unknown frame type"))?;
        let len = r.varint()?;
        if len > ty.max_payload() as u64 {
            return Err(MuxError::Protocol("frame payload over the type limit"));
        }
        Ok(Header {
            stream_id,
            ty,
            len: len as usize,
        })
    })();
    match header {
        Ok(h) => Ok(Some((h, r.position()))),
        Err(MuxError::Decode(DecodeError::Incomplete)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Appends a whole frame. Callers keep `stream_id` within the varint range.
pub(crate) fn encode(stream_id: u64, ty: FrameType, payload: &[u8], out: &mut impl BufMut) {
    put_varint(stream_id, out);
    out.put_u8(ty as u8);
    put_varint(payload.len() as u64, out);
    out.put_slice(payload);
}

/// Encodes a value the caller has already bounded to the varint range.
pub(crate) fn put_varint(value: u64, out: &mut impl BufMut) {
    debug_assert!(value <= varint::MAX);
    varint::encode(value.min(varint::MAX), out).expect("value clamped to the varint range");
}

/// Reads a payload that is exactly one varint.
pub(crate) fn varint_payload(payload: &[u8], what: &'static str) -> Result<u64, MuxError> {
    match varint::decode(payload) {
        Ok((value, len)) if len == payload.len() => Ok(value),
        _ => Err(MuxError::Protocol(what)),
    }
}

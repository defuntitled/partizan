//! Bounds-checked cursor over a receive buffer.

use crate::{DecodeError, varint};

/// Reads fields front to back; running past the end yields [`DecodeError::Incomplete`].
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or(DecodeError::Incomplete)?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16_be(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64_be(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// True once every byte has been consumed.
    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub(crate) fn varint(&mut self) -> Result<u64, DecodeError> {
        let (value, len) = varint::decode(&self.buf[self.pos..])?;
        self.pos += len;
        Ok(value)
    }
}

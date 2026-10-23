//! QUIC variable-length integers (RFC 9000, §16), always minimally encoded.

use bytes::BufMut;

use crate::{DecodeError, EncodeError};

/// Largest encodable value, 2^62 − 1.
pub const MAX: u64 = (1 << 62) - 1;

/// Number of bytes the minimal encoding of `value` takes.
pub fn encoded_len(value: u64) -> Result<usize, EncodeError> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX => Ok(8),
        _ => Err(EncodeError::VarintOverflow(value)),
    }
}

/// Appends the minimal encoding of `value`.
pub fn encode(value: u64, out: &mut impl BufMut) -> Result<(), EncodeError> {
    match encoded_len(value)? {
        1 => out.put_u8(value as u8),
        2 => out.put_u16(0x4000 | value as u16),
        4 => out.put_u32(0x8000_0000 | value as u32),
        _ => out.put_u64(0xc000_0000_0000_0000 | value),
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_to_vec(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode(value, &mut out).unwrap();
    out
}

/// Decodes a varint from the front of `buf`, returning the value and bytes consumed.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), DecodeError> {
    let first = *buf.first().ok_or(DecodeError::Incomplete)?;
    let len = 1 << (first >> 6);
    let bytes = buf.get(..len).ok_or(DecodeError::Incomplete)?;
    let value = bytes[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |acc, &b| acc << 8 | u64::from(b));
    if encoded_len(value) != Ok(len) {
        return Err(DecodeError::NonMinimalVarint);
    }
    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode(value, &mut out).unwrap();
        out
    }

    #[test]
    fn c02_t1_boundary_values_use_1_2_4_8_bytes() {
        for (value, len) in [
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (MAX, 8),
        ] {
            let bytes = enc(value);
            assert_eq!(bytes.len(), len, "length of {value}");
            assert_eq!(decode(&bytes), Ok((value, len)), "roundtrip of {value}");
        }
        // RFC 9000, appendix A.1 examples.
        assert_eq!(enc(151_288_809_941_952_652), hex("c2197c5eff14e88c"));
        assert_eq!(enc(494_878_333), hex("9d7f3e7d"));
        assert_eq!(enc(15_293), hex("7bbd"));
        assert_eq!(enc(37), hex("25"));
        assert_eq!(
            encode(MAX + 1, &mut Vec::new()),
            Err(EncodeError::VarintOverflow(MAX + 1))
        );
    }

    #[test]
    fn c02_t2_non_minimal_varint_is_rejected() {
        // 37 in two bytes is valid per RFC 9000 A.1, but this protocol requires minimal encoding.
        assert_eq!(decode(&hex("4025")), Err(DecodeError::NonMinimalVarint));
        assert_eq!(decode(&hex("80000001")), Err(DecodeError::NonMinimalVarint));
        assert_eq!(
            decode(&hex("c000000000000040")),
            Err(DecodeError::NonMinimalVarint)
        );
    }

    #[test]
    fn truncated_varint_is_incomplete() {
        assert_eq!(decode(&[]), Err(DecodeError::Incomplete));
        assert_eq!(decode(&hex("c2197c5eff14e8")), Err(DecodeError::Incomplete));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}

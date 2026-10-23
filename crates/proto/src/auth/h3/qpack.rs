//! QPACK field sections without a dynamic table (RFC 9204): we advertise capacity 0, so peers
//! may only use the static table and literals. Huffman-coded literals are decoded; we encode
//! literals as plain strings.

use zeroize::Zeroizing;

use super::tables::{HUFFMAN_SORTED, STATIC_TABLE};
use crate::auth::{Fields, ParseError};

/// Longest single name or value.
const MAX_STRING: usize = 8 * 1024;
/// Field section size per RFC 9114 §4.2.2 (name + value + 32 per field).
const MAX_SECTION: usize = 16 * 1024;

/// Upper bound on [`encode`]'s output, so callers can size the buffer once.
pub(crate) fn encoded_len_bound(fields: &[(&str, &str)]) -> usize {
    // Prefix, plus per field up to 10 bytes for each of two length integers.
    2 + fields
        .iter()
        .map(|(n, v)| n.len() + v.len() + 20)
        .sum::<usize>()
}

/// Appends a field section, using static table entries where they match.
pub(crate) fn encode(fields: &[(&str, &str)], out: &mut Vec<u8>) {
    // Required Insert Count 0, Delta Base 0.
    out.extend_from_slice(&[0x00, 0x00]);
    for &(name, value) in fields {
        if let Some(i) = STATIC_TABLE.iter().position(|&e| e == (name, value)) {
            // Indexed field line, static: 11xxxxxx.
            write_int(out, 0xc0, 6, i as u64);
        } else if let Some(i) = STATIC_TABLE.iter().position(|&(n, _)| n == name) {
            // Literal with static name reference, N=0: 0101xxxx.
            write_int(out, 0x50, 4, i as u64);
            write_string(out, 0x00, 7, value);
        } else {
            // Literal with literal name, N=0, H=0: 00100xxx.
            write_string(out, 0x20, 3, name);
            write_string(out, 0x00, 7, value);
        }
    }
}

/// Decodes a complete field section.
pub(crate) fn decode(block: &[u8]) -> Result<Fields, ParseError> {
    let mut pos = 0;
    if read_int(block, &mut pos, 8)? != 0 {
        return Err(ParseError::Malformed("QPACK dynamic table reference"));
    }
    read_int(block, &mut pos, 7)?; // Delta Base is meaningless without a dynamic table.
    let mut fields = Fields(Vec::new());
    let mut size = 0;
    while pos < block.len() {
        let b = block[pos];
        let (name, value) = if b & 0x80 != 0 {
            if b & 0x40 == 0 {
                return Err(ParseError::Malformed("QPACK dynamic table reference"));
            }
            let (name, value) = static_entry(read_int(block, &mut pos, 6)?)?;
            (name.to_owned(), value.to_owned())
        } else if b & 0x40 != 0 {
            if b & 0x10 == 0 {
                return Err(ParseError::Malformed("QPACK dynamic table reference"));
            }
            let (name, _) = static_entry(read_int(block, &mut pos, 4)?)?;
            (name.to_owned(), read_string(block, &mut pos, 7)?)
        } else if b & 0x20 != 0 {
            let name = read_string(block, &mut pos, 3)?;
            (name, read_string(block, &mut pos, 7)?)
        } else {
            // Post-base forms exist only with a dynamic table.
            return Err(ParseError::Malformed("QPACK dynamic table reference"));
        };
        size += name.len() + value.len() + 32;
        if size > MAX_SECTION {
            return Err(ParseError::TooLarge);
        }
        fields.0.push((name, value));
    }
    Ok(fields)
}

fn static_entry(index: u64) -> Result<(&'static str, &'static str), ParseError> {
    usize::try_from(index)
        .ok()
        .and_then(|i| STATIC_TABLE.get(i).copied())
        .ok_or(ParseError::Malformed("QPACK static index out of range"))
}

/// Prefix integer (RFC 7541 §5.1) with `prefix` low bits in the first byte.
fn read_int(buf: &[u8], pos: &mut usize, prefix: u8) -> Result<u64, ParseError> {
    let max = (1u16 << prefix) - 1;
    let first = u16::from(*buf.get(*pos).ok_or(ParseError::Truncated)?) & max;
    *pos += 1;
    if first < max {
        return Ok(first.into());
    }
    let mut value = u64::from(max);
    for shift in (0..=56).step_by(7) {
        let b = *buf.get(*pos).ok_or(ParseError::Truncated)?;
        *pos += 1;
        value += u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ParseError::Malformed("QPACK integer too large"))
}

fn write_int(out: &mut Vec<u8>, flags: u8, prefix: u8, value: u64) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.push(rest as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// String literal whose Huffman flag sits just above a `prefix`-bit length.
fn read_string(buf: &[u8], pos: &mut usize, prefix: u8) -> Result<String, ParseError> {
    let huffman = buf.get(*pos).ok_or(ParseError::Truncated)? & (1 << prefix) != 0;
    let len = read_int(buf, pos, prefix)?;
    let len = usize::try_from(len)
        .ok()
        .filter(|&len| len <= MAX_STRING)
        .ok_or(ParseError::TooLarge)?;
    let raw = buf.get(*pos..*pos + len).ok_or(ParseError::Truncated)?;
    *pos += len;
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        Zeroizing::new(raw.to_vec())
    };
    // Fields we act on are ASCII; anything else only needs to survive being ignored.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn write_string(out: &mut Vec<u8>, flags: u8, prefix: u8, s: &str) {
    write_int(out, flags, prefix, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Decodes the HPACK Huffman code (RFC 7541 Appendix B).
fn huffman_decode(src: &[u8]) -> Result<Zeroizing<Vec<u8>>, ParseError> {
    const BAD: ParseError = ParseError::Malformed("bad Huffman string");
    // Shortest code is 5 bits, so this never reallocates.
    let mut out = Zeroizing::new(Vec::with_capacity(src.len() * 8 / 5));
    let (mut code, mut len) = (0u32, 0u8);
    for &byte in src {
        for bit in (0..8).rev() {
            code = code << 1 | u32::from(byte >> bit & 1);
            len += 1;
            let found = HUFFMAN_SORTED.binary_search_by(|&(l, c, _)| (l, c).cmp(&(len, code)));
            if let Ok(i) = found {
                let symbol = HUFFMAN_SORTED[i].2;
                // EOS inside a string is an error (RFC 7541 §5.2).
                out.push(u8::try_from(symbol).map_err(|_| BAD)?);
                (code, len) = (0, 0);
            } else if len >= 30 {
                return Err(BAD);
            }
        }
    }
    // Padding: under 8 bits, all ones (a prefix of EOS).
    if len > 7 || code != (1 << len) - 1 {
        return Err(BAD);
    }
    Ok(out)
}

/// Huffman-encodes `s`, as a real HTTP/3 stack would; tests only.
#[cfg(test)]
pub(crate) fn huffman_encode(s: &str) -> Vec<u8> {
    use super::tables::HUFFMAN;
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u64, 0u32);
    for &b in s.as_bytes() {
        let (code, len) = HUFFMAN[usize::from(b)];
        acc = acc << len | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 {
        // Pad with the high bits of EOS (all ones).
        out.push((acc << (8 - bits)) as u8 | (0xff >> bits));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::tables::HUFFMAN;
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn tables_match_the_rfcs() {
        // Spot checks against RFC 9204 Appendix A and RFC 7541 Appendix B.
        assert_eq!(STATIC_TABLE[0], (":authority", ""));
        assert_eq!(STATIC_TABLE[20], (":method", "POST"));
        assert_eq!(STATIC_TABLE[25], (":status", "200"));
        assert_eq!(STATIC_TABLE[84], ("authorization", ""));
        assert_eq!(STATIC_TABLE[98], ("x-frame-options", "sameorigin"));
        assert_eq!(HUFFMAN[b'a' as usize], (0x3, 5));
        assert_eq!(HUFFMAN[256], (0x3fff_ffff, 30));
        let mut sorted = HUFFMAN_SORTED;
        sorted.sort();
        assert_eq!(sorted, HUFFMAN_SORTED);
    }

    #[test]
    fn huffman_decodes_rfc_7541_examples() {
        // C.4.1 and C.6.1.
        let cases = [
            ("f1e3 c2e5 f23a 6ba0 ab90 f4ff", "www.example.com"),
            ("6402", "302"),
            ("aec3 771a 4b", "private"),
            (
                "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3",
                "https://www.example.com",
            ),
        ];
        for (hex, text) in cases {
            assert_eq!(
                huffman_decode(&unhex(hex)).unwrap().as_slice(),
                text.as_bytes()
            );
        }
        // Padding of 8+ bits, padding with a zero bit, and an explicit EOS are rejected.
        assert!(huffman_decode(&unhex("f1e3 c2e5 f23a 6ba0 ab90 f4ff ff")).is_err());
        assert!(huffman_decode(&unhex("f1e3 c2e5 f23a 6ba0 ab90 f4fe")).is_err());
        assert!(huffman_decode(&unhex("ffff fffc")).is_err());
    }

    fn enc(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(fields, &mut out);
        assert!(out.len() <= encoded_len_bound(fields));
        out
    }

    fn dec(block: &[u8]) -> Result<Vec<(String, String)>, ParseError> {
        decode(block).map(|f| f.0.clone())
    }

    #[test]
    fn field_section_matches_rfc_9204_example() {
        // B.1: literal with static name reference, :path=/index.html.
        let block = unhex("0000 510b 2f69 6e64 6578 2e68 746d 6c");
        assert_eq!(
            dec(&block).unwrap(),
            [(":path".to_owned(), "/index.html".to_owned())]
        );
        assert_eq!(enc(&[(":path", "/index.html")]), block);
    }

    #[test]
    fn field_section_roundtrips_and_rejects_dynamic_references() {
        let long = "a".repeat(300);
        let fields = [
            (":status", "200"),
            ("authorization", "Bearer x"),
            ("x-session", "v=1"),
            ("x-long", long.as_str()),
        ];
        let decoded = dec(&enc(&fields)).unwrap();
        let back: Vec<(&str, &str)> = decoded
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(back, fields);
        // Indexed :status 200 encodes to one byte: 0xc0 | 25.
        assert_eq!(enc(&[(":status", "200")]), [0x00, 0x00, 0xd9]);

        for bad in [
            "0100",
            "0000 80",
            "0000 40",
            "0000 10",
            "0000 00",
            "0000 ff 64",
        ] {
            assert!(dec(&unhex(bad)).is_err(), "{bad}");
        }
        // Truncated string, an oversized length, and an integer with 10 continuation bytes.
        assert_eq!(dec(&unhex("0000 510b 2f69")), Err(ParseError::Truncated));
        assert_eq!(
            dec(&unhex("0000 51 ff ff ff 0f")),
            Err(ParseError::TooLarge)
        );
        assert!(matches!(
            dec(&unhex("0000 ff ff ff ff ff ff ff ff ff ff 01")),
            Err(ParseError::Malformed(_))
        ));
    }

    #[test]
    fn huffman_literals_decode() {
        // Literal with literal name, both Huffman-coded, as HTTP/3 stacks send them.
        let (name, value) = ("x-session", "v=1; caps=7; sid=ab; udp-max=1200");
        let (hn, hv) = (huffman_encode(name), huffman_encode(value));
        let mut block = vec![0x00, 0x00];
        write_int(&mut block, 0x28, 3, hn.len() as u64);
        block.extend_from_slice(&hn);
        write_int(&mut block, 0x80, 7, hv.len() as u64);
        block.extend_from_slice(&hv);
        assert_eq!(dec(&block).unwrap(), [(name.to_owned(), value.to_owned())]);
        // The encoder agrees with RFC 7541 C.4.1.
        assert_eq!(
            huffman_encode("www.example.com"),
            unhex("f1e3 c2e5 f23a 6ba0 ab90 f4ff")
        );
    }
}

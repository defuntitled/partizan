//! TLS ClientHello parsing (RFC 8446 §4.1.2), sans-io: for JA4 fingerprints and for reading the
//! passthrough mark before any TLS library sees the connection.

use sha2::{Digest, Sha256};

use crate::reader::Reader;

/// Largest ClientHello accepted (Chrome's with a post-quantum key share is ~1.8 KiB).
pub const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Extension types used here.
pub mod ext {
    /// server_name.
    pub const SERVER_NAME: u16 = 0x0000;
    /// signature_algorithms.
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// application_layer_protocol_negotiation.
    pub const ALPN: u16 = 0x0010;
    /// supported_versions.
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// key_share.
    pub const KEY_SHARE: u16 = 0x0033;
}

/// A parsed ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// `client_random`.
    pub random: [u8; 32],
    /// `legacy_session_id` (0..=32 bytes).
    pub session_id: Vec<u8>,
    /// Cipher suites in order.
    pub cipher_suites: Vec<u16>,
    /// Extensions in order: type and body.
    pub extensions: Vec<(u16, Vec<u8>)>,
    /// The handshake message itself (type, length, body), as signed for the passthrough mark.
    pub raw: Vec<u8>,
    /// Offset of `legacy_session_id`'s bytes within [`ClientHello::raw`].
    pub session_id_offset: usize,
}

/// Why bytes are not a ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HelloError {
    /// More bytes are needed.
    #[error("incomplete")]
    Incomplete,
    /// Not a TLS handshake starting with a ClientHello, or malformed.
    #[error("not a ClientHello")]
    NotClientHello,
}

/// GREASE values (RFC 8701): 0x?A?A with both bytes equal.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

/// Reassembles the ClientHello from TLS records at the front of `buf`.
pub fn parse(buf: &[u8]) -> Result<ClientHello, HelloError> {
    // Handshake records (type 22) carry the message, possibly split across several.
    let mut message = Vec::new();
    let mut pos = 0;
    loop {
        let header = buf.get(pos..pos + 5).ok_or(HelloError::Incomplete)?;
        if header[0] != 22 || header[1] != 3 {
            return Err(HelloError::NotClientHello);
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        // A plaintext TLS record cannot exceed 2^14 bytes. Reject its length before
        // waiting for or copying attacker-controlled payloads.
        if len > MAX_CLIENT_HELLO {
            return Err(HelloError::NotClientHello);
        }
        let body = buf
            .get(pos + 5..pos + 5 + len)
            .ok_or(HelloError::Incomplete)?;
        let room = MAX_CLIENT_HELLO - message.len();
        message.extend_from_slice(&body[..body.len().min(room)]);
        pos += 5 + len;
        if message.len() >= 4 {
            if message[0] != 1 {
                return Err(HelloError::NotClientHello);
            }
            let want = 4
                + (usize::from(message[1]) << 16
                    | usize::from(message[2]) << 8
                    | usize::from(message[3]));
            if want > MAX_CLIENT_HELLO {
                return Err(HelloError::NotClientHello);
            }
            if message.len() >= want {
                message.truncate(want);
                return parse_message(message);
            }
        }
    }
}

fn parse_message(raw: Vec<u8>) -> Result<ClientHello, HelloError> {
    let bad = |_| HelloError::NotClientHello;
    let mut r = Reader::new(&raw[4..]);
    let _legacy_version = r.u16_be().map_err(bad)?;
    let random = r.array::<32>().map_err(bad)?;
    let sid_len = usize::from(r.u8().map_err(bad)?);
    if sid_len > 32 {
        return Err(HelloError::NotClientHello);
    }
    let session_id_offset = 4 + r.position();
    let session_id = r.bytes(sid_len).map_err(bad)?.to_vec();
    let suites_len = usize::from(r.u16_be().map_err(bad)?);
    let suites = r.bytes(suites_len).map_err(bad)?;
    if suites_len % 2 != 0 {
        return Err(HelloError::NotClientHello);
    }
    let cipher_suites = suites
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let comp_len = usize::from(r.u8().map_err(bad)?);
    r.bytes(comp_len).map_err(bad)?;
    let mut extensions = Vec::new();
    if !r.is_empty() {
        let ext_len = usize::from(r.u16_be().map_err(bad)?);
        let mut e = Reader::new(r.bytes(ext_len).map_err(bad)?);
        while !e.is_empty() {
            let ty = e.u16_be().map_err(bad)?;
            let len = usize::from(e.u16_be().map_err(bad)?);
            extensions.push((ty, e.bytes(len).map_err(bad)?.to_vec()));
        }
    }
    Ok(ClientHello {
        random,
        session_id,
        cipher_suites,
        extensions,
        raw,
        session_id_offset,
    })
}

impl ClientHello {
    /// Body of the first extension of type `ty`.
    pub fn extension(&self, ty: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, b)| b.as_slice())
    }

    /// Host name from server_name.
    pub fn server_name(&self) -> Option<String> {
        let mut r = Reader::new(self.extension(ext::SERVER_NAME)?);
        let _list_len = r.u16_be().ok()?;
        while !r.is_empty() {
            let kind = r.u8().ok()?;
            let len = usize::from(r.u16_be().ok()?);
            let name = r.bytes(len).ok()?;
            if kind == 0 {
                return String::from_utf8(name.to_vec()).ok();
            }
        }
        None
    }

    /// ALPN protocols offered, in order.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        let Some(body) = self.extension(ext::ALPN) else {
            return Vec::new();
        };
        let mut r = Reader::new(body);
        let mut out = Vec::new();
        if r.u16_be().is_ok() {
            while let Ok(len) = r.u8() {
                match r.bytes(usize::from(len)) {
                    Ok(p) => out.push(p.to_vec()),
                    Err(_) => break,
                }
            }
        }
        out
    }

    fn u16_list(body: &[u8], len_bytes: usize) -> Vec<u16> {
        body.get(len_bytes..)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    /// Versions from supported_versions.
    pub fn supported_versions(&self) -> Vec<u16> {
        self.extension(ext::SUPPORTED_VERSIONS)
            .map(|b| Self::u16_list(b, 1))
            .unwrap_or_default()
    }

    /// Signature algorithms in order.
    pub fn signature_algorithms(&self) -> Vec<u16> {
        self.extension(ext::SIGNATURE_ALGORITHMS)
            .map(|b| Self::u16_list(b, 2))
            .unwrap_or_default()
    }

    /// Key shares: group and key exchange bytes.
    pub fn key_shares(&self) -> Vec<(u16, Vec<u8>)> {
        let Some(body) = self.extension(ext::KEY_SHARE) else {
            return Vec::new();
        };
        let mut r = Reader::new(body);
        let mut out = Vec::new();
        if r.u16_be().is_ok() {
            while let (Ok(group), Ok(len)) = (r.u16_be(), r.u16_be()) {
                match r.bytes(usize::from(len)) {
                    Ok(key) => out.push((group, key.to_vec())),
                    Err(_) => break,
                }
            }
        }
        out
    }

    /// JA4 fingerprint (FoxIO), TCP variant: `t13d1516h2_<ciphers>_<extensions>`.
    pub fn ja4(&self) -> String {
        let version = match self
            .supported_versions()
            .into_iter()
            .filter(|v| !is_grease(*v))
            .max()
        {
            Some(0x0304) => "13",
            Some(0x0303) => "12",
            Some(0x0302) => "11",
            Some(0x0301) => "10",
            _ => "00",
        };
        let sni = match self.server_name() {
            Some(name) if name.parse::<std::net::IpAddr>().is_err() => 'd',
            _ => 'i',
        };
        let ciphers: Vec<u16> = self
            .cipher_suites
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();
        let exts: Vec<u16> = self
            .extensions
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| !is_grease(*t))
            .collect();
        let alpn = match self.alpn().first() {
            Some(p) if !p.is_empty() => {
                let (first, last) = (p[0] as char, p[p.len() - 1] as char);
                if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
                    format!("{first}{last}")
                } else {
                    let hex = crate::auth::encoding::hex(p);
                    format!("{}{}", &hex[..1], &hex[hex.len() - 1..])
                }
            }
            _ => "00".into(),
        };
        let hex_list = |v: &[u16]| {
            v.iter()
                .map(|x| format!("{x:04x}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let hash12 =
            |s: &str| crate::auth::encoding::hex(&Sha256::digest(s.as_bytes()))[..12].to_owned();
        let mut sorted_ciphers = ciphers.clone();
        sorted_ciphers.sort_unstable();
        let mut sorted_exts: Vec<u16> = exts
            .iter()
            .copied()
            .filter(|t| *t != ext::SERVER_NAME && *t != ext::ALPN)
            .collect();
        sorted_exts.sort_unstable();
        let sigalgs = self.signature_algorithms();
        let ext_input = if sigalgs.is_empty() {
            hex_list(&sorted_exts)
        } else {
            format!("{}_{}", hex_list(&sorted_exts), hex_list(&sigalgs))
        };
        format!(
            "t{version}{sni}{:02}{:02}{alpn}_{}_{}",
            ciphers.len().min(99),
            exts.len().min(99),
            hash12(&hex_list(&sorted_ciphers)),
            hash12(&ext_input)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Chrome-shaped ClientHello assembled by hand from the published lists.
    fn chrome_like() -> Vec<u8> {
        let ciphers: [u16; 16] = [
            0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let mut exts: Vec<(u16, Vec<u8>)> = vec![(0x1a1a, vec![])];
        let name = b"cdn.example.com";
        let mut sni = vec![0, (name.len() + 3) as u8, 0, 0, name.len() as u8];
        sni.extend_from_slice(name);
        exts.push((0x0000, sni));
        for t in [
            0x0005u16, 0x000a, 0x000b, 0x0012, 0x0017, 0x001b, 0x0023, 0x002d, 0x0033, 0x44cd,
            0xfe0d, 0xff01,
        ] {
            exts.push((t, vec![]));
        }
        let sig: [u16; 8] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut sig_body = ((sig.len() * 2) as u16).to_be_bytes().to_vec();
        sig.iter()
            .for_each(|s| sig_body.extend_from_slice(&s.to_be_bytes()));
        exts.push((0x000d, sig_body));
        exts.push((
            0x0010,
            vec![
                0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
            ],
        ));
        exts.push((0x002b, vec![6, 0x3a, 0x3a, 0x03, 0x04, 0x03, 0x03]));
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(32);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        ciphers
            .iter()
            .for_each(|c| body.extend_from_slice(&c.to_be_bytes()));
        body.extend_from_slice(&[1, 0]);
        let mut ext_bytes = Vec::new();
        for (t, b) in &exts {
            ext_bytes.extend_from_slice(&t.to_be_bytes());
            ext_bytes.extend_from_slice(&(b.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(b);
        }
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        body.extend(ext_bytes);
        let mut msg = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        msg.extend(body);
        let mut rec = vec![22, 3, 1, (msg.len() >> 8) as u8, msg.len() as u8];
        rec.extend(msg);
        rec
    }

    #[test]
    fn chrome_lists_give_chromes_ja4() {
        let hello = parse(&chrome_like()).unwrap();
        assert_eq!(hello.server_name().as_deref(), Some("cdn.example.com"));
        assert_eq!(hello.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(hello.session_id, [9u8; 32]);
        assert_eq!(
            &hello.raw[hello.session_id_offset..hello.session_id_offset + 32],
            &[9u8; 32]
        );
        assert_eq!(hello.ja4(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");
    }

    #[test]
    fn truncated_and_foreign_input() {
        let full = chrome_like();
        for cut in [0, 3, 5, 40, full.len() - 1] {
            assert_eq!(
                parse(&full[..cut]),
                Err(HelloError::Incomplete),
                "cut {cut}"
            );
        }
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\n\r\n"),
            Err(HelloError::NotClientHello)
        );
        // The same hello split over two records reassembles.
        let msg = &full[5..];
        let mut split = vec![22, 3, 1, 0, 10];
        split.extend_from_slice(&msg[..10]);
        split.extend_from_slice(&[
            22,
            3,
            1,
            ((msg.len() - 10) >> 8) as u8,
            (msg.len() - 10) as u8,
        ]);
        split.extend_from_slice(&msg[10..]);
        assert_eq!(parse(&split).unwrap().ja4(), parse(&full).unwrap().ja4());
        assert!(is_grease(0x2a2a) && is_grease(0xfafa) && !is_grease(0x1301));
    }

    #[test]
    fn c23_t3_oversize_record_is_rejected_before_its_payload_arrives() {
        assert_eq!(
            parse(&[22, 3, 1, 0xff, 0xff]),
            Err(HelloError::NotClientHello)
        );
    }
}

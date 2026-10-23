//! Device credentials: id, token and the token hash the server stores.

use std::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::encoding::{base64url, hex, unbase64url, unhex};

/// Device identifier: 16 random bytes, written as 32 lowercase hex characters. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    /// Random new id.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut id = [0; 16];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }

    /// Parses 32 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        unhex(s).map(Self)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

/// Device token: 32 random bytes.
///
/// No `Debug` and no `PartialEq` on purpose: it is zeroed on drop and only ever compared through
/// [`TokenHash::matches`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Token([u8; 32]);

impl Token {
    /// Random new token.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut token = Self([0; 32]);
        getrandom::fill(&mut token.0)?;
        Ok(token)
    }

    /// Wraps raw token bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Unpadded base64url, as in headers and the connection URI.
    pub fn to_base64url(&self) -> Zeroizing<String> {
        Zeroizing::new(base64url(&self.0))
    }

    /// Parses unpadded base64url of exactly 32 bytes.
    pub fn from_base64url(s: &str) -> Option<Self> {
        let mut bytes = Zeroizing::new(unbase64url::<32>(s)?);
        Some(Self(std::mem::take(&mut *bytes)))
    }

    /// SHA-256 of the token, the only form the server stores.
    pub fn hash(&self) -> TokenHash {
        TokenHash(Sha256::digest(self.0).into())
    }
}

/// SHA-256 of a [`Token`]. Not secret on its own, but compared only in constant time.
#[derive(Clone, Copy)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Stand-in compared against when the device is unknown, so that path costs the same.
    pub(crate) const DUMMY: Self = Self([0; 32]);

    /// Constant-time comparison.
    pub fn matches(&self, other: &TokenHash) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Lowercase hex, for the device registry file.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// Parses 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        unhex(s).map(Self)
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenHash({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn credentials_roundtrip() {
        let id = DeviceId::generate().unwrap();
        assert_eq!(id.to_string().len(), 32);
        assert_eq!(DeviceId::from_hex(&id.to_string()), Some(id));
        let token = Token::generate().unwrap();
        let parsed = Token::from_base64url(&token.to_base64url()).unwrap();
        assert!(parsed.hash().matches(&token.hash()));
        let hash = token.hash();
        assert!(TokenHash::from_hex(&hash.to_hex()).unwrap().matches(&hash));
        // SHA-256 of 32 zero bytes.
        assert_eq!(
            Token::from_bytes([0; 32]).hash().to_hex(),
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }

    #[test]
    fn c05_t8_token_is_zeroed_and_kept_out_of_debug() {
        assert_zeroize_on_drop::<Token>();
        let mut token = Token::from_bytes([0xab; 32]);
        token.zeroize();
        assert_eq!(token.0, [0; 32]);
        // Debug output of the hash never contains the token itself.
        let token = Token::from_bytes([0xcd; 32]);
        let shown = format!("{:?}", token.hash());
        assert!(!shown.contains(&hex(&token.0)));
        assert!(!shown.contains(token.to_base64url().as_str()));
    }

    /// Fastest of many batches per input class; the minimum filters out scheduler noise.
    fn fastest(hash: &TokenHash, candidate: &TokenHash) -> u128 {
        (0..50)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..2_000 {
                    std::hint::black_box(std::hint::black_box(hash).matches(candidate));
                }
                start.elapsed().as_nanos()
            })
            .min()
            .unwrap()
    }

    #[test]
    fn c05_t7_token_comparison_is_constant_time() {
        let stored = Token::from_bytes([0x11; 32]).hash();
        let mut first_byte = stored;
        first_byte.0[0] ^= 1;
        let mut last_byte = stored;
        last_byte.0[31] ^= 1;
        // Warm up, then interleave so drift affects all classes alike.
        fastest(&stored, &stored);
        let mut times = [0u128; 3];
        for _ in 0..5 {
            times[0] += fastest(&stored, &stored);
            times[1] += fastest(&stored, &first_byte);
            times[2] += fastest(&stored, &last_byte);
        }
        let (min, max) = (times.iter().min().unwrap(), times.iter().max().unwrap());
        // A byte-by-byte early exit differs by far more than this between first and last byte.
        // A vectorized memcmp over 32 bytes would not show here at all, which is why the compare
        // goes through `subtle` rather than relying on this test.
        assert!(
            *max as f64 / *min as f64 <= 1.5,
            "equal / first-byte / last-byte mismatch: {times:?} ns"
        );
    }
}

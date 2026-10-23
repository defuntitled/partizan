//! rustls configs for both transports: TLS 1.3 only, `ring` provider.
//!
//! The client verifies the server against Mozilla's roots or, when the connection URI carries
//! a pin, by the SHA-256 of the certificate's SubjectPublicKeyInfo alone (so self-signed works).

use std::sync::Arc;

use proto::auth::ConnectionUri;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// ALPN for QUIC.
pub const ALPN_H3: &[u8] = b"h3";
/// ALPN the server selects on TCP+TLS.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// `ring` with TLS 1.3 suites only, AES-128-GCM first as in Chrome.
pub fn provider() -> Arc<CryptoProvider> {
    let mut provider = ring::default_provider();
    provider.cipher_suites = vec![
        ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    Arc::new(provider)
}

/// How the client checks the server certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerVerification {
    /// Chain to Mozilla's roots, name must match.
    WebPki,
    /// SHA-256 of the end-entity SPKI must equal this.
    Pin([u8; 32]),
    /// Accept any certificate (tests only); handshake signatures are still checked.
    Insecure,
}

impl ServerVerification {
    /// Pin if the URI has one, else `insecure`, else the web PKI.
    pub fn from_uri(uri: &ConnectionUri) -> Self {
        match (uri.pin, uri.insecure) {
            (Some(pin), _) => Self::Pin(pin),
            (None, true) => Self::Insecure,
            (None, false) => Self::WebPki,
        }
    }
}

/// Client config with the given verification and ALPN list. 0-RTT stays off; session
/// resumption (1-RTT) is on by default.
pub fn client_config(
    verification: ServerVerification,
    alpn: &[&[u8]],
) -> Result<rustls::ClientConfig, Error> {
    let provider = provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = match verification {
        ServerVerification::WebPki => {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        ServerVerification::Pin(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(KeyVerifier::new(Some(pin), &provider)))
            .with_no_client_auth(),
        ServerVerification::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(KeyVerifier::new(None, &provider)))
            .with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.enable_early_data = false;
    Ok(config)
}

/// Server config for one certificate chain. Early data is refused (`max_early_data_size` 0).
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, Error> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.max_early_data_size = 0;
    Ok(config)
}

/// Accepts a certificate whose SPKI matches the pin (or any, without one) but always checks
/// the handshake signature, so the server must hold the key.
#[derive(Debug)]
struct KeyVerifier {
    pin: Option<[u8; 32]>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl KeyVerifier {
    fn new(pin: Option<[u8; 32]>, provider: &CryptoProvider) -> Self {
        Self {
            pin,
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for KeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let Some(pin) = self.pin else {
            return Ok(ServerCertVerified::assertion());
        };
        let spki =
            spki(end_entity).ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let digest: [u8; 32] = Sha256::digest(spki).into();
        if bool::from(digest.ct_eq(&pin)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// SHA-256 of the certificate's SubjectPublicKeyInfo: the value a URI pin carries.
pub fn spki_pin(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    spki(cert).map(|spki| Sha256::digest(spki).into())
}

/// DER of the SubjectPublicKeyInfo inside an X.509 certificate (RFC 5280 §4.1).
fn spki<'a>(cert: &'a CertificateDer<'_>) -> Option<&'a [u8]> {
    let (certificate, _) = der_contents(cert, 0x30)?;
    let (tbs, _) = der_contents(certificate, 0x30)?;
    let mut rest = tbs;
    // Optional `[0] EXPLICIT Version`.
    if rest.first() == Some(&0xa0) {
        rest = &rest[der_contents(rest, 0xa0)?.1..];
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        let len = der_tlv_len(rest)?;
        rest = &rest[len..];
    }
    let (_, len) = der_contents(rest, 0x30)?;
    Some(&rest[..len])
}

/// Contents of a TLV with the expected tag, and the TLV's total length.
fn der_contents(buf: &[u8], tag: u8) -> Option<(&[u8], usize)> {
    if *buf.first()? != tag {
        return None;
    }
    let total = der_tlv_len(buf)?;
    let header = total - der_len(buf)?.0;
    Some((&buf[header..total], total))
}

/// Total length of the TLV at the front of `buf`.
fn der_tlv_len(buf: &[u8]) -> Option<usize> {
    let (len, header) = der_len(buf)?;
    let total = header.checked_add(len)?;
    (total <= buf.len()).then_some(total)
}

/// Content length and header size (tag + length bytes); definite lengths up to 4 bytes.
fn der_len(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.get(1)?;
    if first < 0x80 {
        return Some((usize::from(first), 2));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return None;
    }
    let len = buf
        .get(2..2 + n)?
        .iter()
        .fold(0usize, |acc, &b| acc << 8 | usize::from(b));
    Some((len, 2 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_matches_the_generated_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der();
        let public = rcgen::PublicKeyData::subject_public_key_info(&key);
        assert_eq!(spki(der), Some(public.as_slice()));
        let expected: [u8; 32] = Sha256::digest(&public).into();
        assert_eq!(spki_pin(der), Some(expected));
        // Truncated or garbage input yields nothing rather than panicking.
        for cut in [0, 1, 10, der.len() / 2] {
            assert_eq!(spki(&CertificateDer::from(&der[..cut])), None);
        }
    }

    #[test]
    fn c07_t3_tls13_with_aes_128_gcm_is_negotiated() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pin = spki_pin(cert.der()).unwrap();
        let server = server_config(
            vec![cert.der().clone()],
            PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            &[ALPN_H3],
        )
        .unwrap();
        let client = client_config(ServerVerification::Pin(pin), &[ALPN_H3]).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut c = rustls::ClientConnection::new(Arc::new(client), name).unwrap();
        let mut s = rustls::ServerConnection::new(Arc::new(server)).unwrap();
        // Shuttle handshake records in memory until both sides are done.
        for _ in 0..10 {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets().unwrap();
            buf.clear();
            s.write_tls(&mut buf).unwrap();
            c.read_tls(&mut &buf[..]).unwrap();
            c.process_new_packets().unwrap();
        }
        assert!(!c.is_handshaking());
        assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        assert_eq!(
            c.negotiated_cipher_suite().map(|s| s.suite()),
            Some(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        );
        assert_eq!(c.alpn_protocol(), Some(ALPN_H3));
    }

    #[test]
    fn wrong_pin_is_refused() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let verifier = KeyVerifier::new(Some([0; 32]), &provider());
        let name = ServerName::try_from("localhost").unwrap();
        let result = verifier.verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now());
        assert!(result.is_err());
    }
}

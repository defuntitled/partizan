//! Client TLS over TCP on BoringSSL, shaped like stable Chrome so DPI sees a browser.
//!
//! The profile is data ([`PROFILE`]): update it from a capture of a real Chrome when Chrome
//! changes. Certificates are still checked by us (pin or web PKI) in BoringSSL's verify
//! callback; BoringSSL checks the handshake signature.

use std::io;
use std::net::SocketAddr;

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslAlert, SslConnector, SslMethod,
    SslVerifyError, SslVerifyMode, SslVersion,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::tls::{ServerVerification, spki_pin};

/// A browser's ClientHello settings.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    /// Browser and version the profile was taken from.
    pub name: &'static str,
    /// TLS 1.2 cipher list in Chrome's order (BoringSSL fixes the TLS 1.3 ones to Chrome's).
    pub cipher_list: &'static str,
    /// Groups, first ones get key shares.
    pub curves: &'static str,
    /// Signature algorithms in order.
    pub sigalgs: &'static str,
    /// ALPN offered.
    pub alpn: &'static [&'static [u8]],
    /// ALPS settings sent for this protocol, on the new codepoint (0x44cd).
    pub alps_protocol: &'static [u8],
    /// JA4 a real capture of this browser gives; the CI test compares against it.
    pub ja4: &'static str,
}

/// Stable Chrome (desktop, since the switch to the new ALPS codepoint, v133+).
pub const PROFILE: Profile = Profile {
    name: "Chrome 133+",
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
    curves: "X25519MLKEM768:X25519:P-256:P-384",
    sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
              ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
              rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
    alpn: &[b"h2", b"http/1.1"],
    alps_protocol: b"h2",
    ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
};

/// Chrome advertises brotli certificate compression; decompression only.
pub(crate) struct Brotli;

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: io::Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        brotli_decompressor::BrotliDecompress(&mut &input[..], output)
    }
}

/// TCP plus a Chrome-shaped TLS handshake to `addr` with SNI `server_name`.
pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    verification: ServerVerification,
) -> io::Result<SslStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    connect_stream(tcp, server_name, verification).await
}

/// The handshake over an existing TCP stream.
pub async fn connect_stream(
    tcp: TcpStream,
    server_name: &str,
    verification: ServerVerification,
) -> io::Result<SslStream<TcpStream>> {
    let connector = connector(server_name.to_owned(), verification).map_err(io::Error::other)?;
    let mut config = connector.configure().map_err(io::Error::other)?;
    config.set_enable_ech_grease(true);
    add_alps(&mut config)?;
    // Our own verify callback decides; BoringSSL's hostname check would use the system store.
    config.set_verify_hostname(false);
    config.set_use_server_name_indication(true);
    tokio_boring::connect(config, server_name, tcp)
        .await
        .map_err(|e| io::Error::other(e.to_string()))
}

fn connector(
    server_name: String,
    verification: ServerVerification,
) -> Result<SslConnector, boring::error::ErrorStack> {
    let p = &PROFILE;
    let mut b = SslConnector::builder(SslMethod::tls())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_cipher_list(p.cipher_list)?;
    b.set_curves_list(p.curves)?;
    b.set_sigalgs_list(p.sigalgs)?;
    b.set_grease_enabled(true);
    b.set_permute_extensions(true);
    b.enable_ocsp_stapling();
    b.enable_signed_cert_timestamps();
    b.add_certificate_compression_algorithm(Brotli)?;
    let mut wire = Vec::new();
    for proto in p.alpn {
        wire.push(proto.len() as u8);
        wire.extend_from_slice(proto);
    }
    b.set_alpn_protos(&wire)?;
    b.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        let chain: Vec<Vec<u8>> = ssl
            .peer_cert_chain()
            .map(|chain| chain.iter().filter_map(|c| c.to_der().ok()).collect())
            .unwrap_or_default();
        verify(&chain, &server_name, verification)
            .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
    });
    Ok(b.build())
}

/// ALPS (application_settings) as Chrome sends it: empty h2 settings, new codepoint.
fn add_alps(ssl: &mut boring::ssl::SslRef) -> io::Result<()> {
    let proto = PROFILE.alps_protocol;
    // SAFETY: `ssl` is a live SSL object owned by the connection being configured; BoringSSL
    // copies `proto` (and the empty settings) before returning.
    let ok = unsafe {
        let raw = foreign_types::ForeignTypeRef::as_ptr(ssl);
        boring_sys::SSL_set_alps_use_new_codepoint(raw, 1);
        boring_sys::SSL_add_application_settings(
            raw,
            proto.as_ptr(),
            proto.len(),
            std::ptr::null(),
            0,
        )
    };
    if ok == 1 {
        Ok(())
    } else {
        Err(io::Error::other("ALPS setup failed"))
    }
}

/// Checks the server's chain (leaf first) like the rustls client does.
pub(crate) fn verify(
    chain: &[Vec<u8>],
    server_name: &str,
    verification: ServerVerification,
) -> Result<(), ()> {
    let leaf = chain.first().ok_or(())?;
    match verification {
        ServerVerification::Insecure => Ok(()),
        ServerVerification::Pin(pin) => {
            let got = spki_pin(&CertificateDer::from(leaf.as_slice())).ok_or(())?;
            if bool::from(subtle::ConstantTimeEq::ct_eq(&got[..], &pin[..])) {
                Ok(())
            } else {
                Err(())
            }
        }
        ServerVerification::WebPki => {
            let leaf = CertificateDer::from(leaf.as_slice());
            let cert = webpki::EndEntityCert::try_from(&leaf).map_err(|_| ())?;
            let intermediates: Vec<CertificateDer<'_>> = chain[1..]
                .iter()
                .map(|c| CertificateDer::from(c.as_slice()))
                .collect();
            let algorithms =
                rustls::crypto::ring::default_provider().signature_verification_algorithms;
            cert.verify_for_usage(
                algorithms.all,
                webpki_roots::TLS_SERVER_ROOTS,
                &intermediates,
                UnixTime::now(),
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|_| ())?;
            let name = ServerName::try_from(server_name).map_err(|_| ())?;
            cert.verify_is_valid_for_subject_name(&name).map_err(|_| ())
        }
    }
}

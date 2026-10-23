//! BoringSSL client with the Chrome profile: its ClientHello fingerprint, and a full session
//! against the rustls server side.

#![cfg(feature = "chrome")]

use std::sync::Arc;
use std::time::Duration;

use proto::tls_hello;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use transport::chrome::{self, PROFILE};
use transport::tls::{self, ALPN_HTTP11, ServerVerification};

/// The ClientHello our client sends, as seen by a listener that never answers.
async fn capture_client_hello() -> tls_hello::ClientHello {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move {
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            chrome::connect(addr, "cdn.example.com", ServerVerification::Insecure),
        )
        .await;
    });
    let (mut tcp, _) = listener.accept().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let hello = loop {
        let n = tcp.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before a ClientHello");
        buf.extend_from_slice(&chunk[..n]);
        match tls_hello::parse(&buf) {
            Ok(hello) => break hello,
            Err(tls_hello::HelloError::Incomplete) => continue,
            Err(e) => panic!("{e}"),
        }
    };
    client.abort();
    hello
}

#[tokio::test]
async fn c21_t1_t4_ja4_matches_the_chrome_profile() {
    let hello = capture_client_hello().await;
    assert_eq!(
        hello.ja4(),
        PROFILE.ja4,
        "JA4 drifted from {}",
        PROFILE.name
    );
    // What JA4 does not cover but Chrome does: GREASE, the hybrid post-quantum share, ALPS on the
    // new codepoint, and an ECH GREASE extension.
    assert!(
        hello.cipher_suites.iter().any(|c| tls_hello::is_grease(*c)),
        "no GREASE cipher"
    );
    let groups: Vec<u16> = hello.key_shares().iter().map(|(g, _)| *g).collect();
    assert!(
        groups.contains(&0x11ec),
        "no X25519MLKEM768 key share: {groups:04x?}"
    );
    assert!(
        groups.contains(&0x001d),
        "no X25519 key share: {groups:04x?}"
    );
    for ext in [0x44cd, 0xfe0d, 0x001b] {
        assert!(
            hello.extension(ext).is_some(),
            "missing extension {ext:#06x}"
        );
    }
    assert_eq!(
        hello.session_id.len(),
        32,
        "Chrome always sends a 32-byte session id"
    );
}

#[tokio::test]
async fn extension_order_is_permuted_like_chrome() {
    let order = |h: &tls_hello::ClientHello| {
        h.extensions
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| !tls_hello::is_grease(*t))
            .collect::<Vec<_>>()
    };
    let first = order(&capture_client_hello().await);
    let mut differs = false;
    for _ in 0..5 {
        if order(&capture_client_hello().await) != first {
            differs = true;
            break;
        }
    }
    assert!(differs, "extension order never changed");
}

#[tokio::test]
async fn c21_t2_full_session_against_the_rustls_server() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pin = tls::spki_pin(cert.der()).unwrap();
    let config = tls::server_config(
        vec![cert.der().clone()],
        PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        &[ALPN_HTTP11],
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 5];
                    if tls.read_exact(&mut buf).await.is_ok() {
                        let _ = tls.write_all(&buf).await;
                        let _ = tls.shutdown().await;
                    }
                }
            });
        }
    });
    let mut stream = chrome::connect(addr, "localhost", ServerVerification::Pin(pin))
        .await
        .unwrap();
    assert_eq!(stream.ssl().selected_alpn_protocol(), Some(ALPN_HTTP11));
    assert_eq!(stream.ssl().version_str(), "TLSv1.3");
    stream.write_all(b"hello").await.unwrap();
    let mut back = [0u8; 5];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"hello");
    // A wrong pin fails the handshake.
    assert!(
        chrome::connect(addr, "localhost", ServerVerification::Pin([0; 32]))
            .await
            .is_err()
    );
}

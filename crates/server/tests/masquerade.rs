//! Visitors without a token: the server answers as an ordinary website over HTTPS and HTTP/3.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use proto::auth::web;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport::QuicConfig;
use transport::tls::{self, ALPN_H3, ALPN_HTTP11, ServerVerification};

/// One HTTP/1.1 exchange over TLS; returns status, header names (lowercase, sorted) and body.
async fn https(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &str,
) -> (u16, Vec<String>, Vec<u8>) {
    let config = tls::client_config(ServerVerification::Insecure, &[b"h2", ALPN_HTTP11]).unwrap();
    let mut tls = transport::tcp::connect_tls(addr, "localhost", config)
        .await
        .unwrap();
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut raw)).await;
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut names: Vec<String> = lines
        .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
        .collect();
    names.sort();
    let len: usize = head
        .split("\r\n")
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(|v| v.parse().unwrap())
        })
        .unwrap();
    (status, names, raw[end + 4..end + 4 + len].to_vec())
}

/// One HTTP/3 request on a fresh connection; returns status, header names and body.
async fn h3(addr: SocketAddr, method: &str, path: &str) -> (u16, Vec<String>, Vec<u8>) {
    let config = tls::client_config(ServerVerification::Insecure, &[ALPN_H3]).unwrap();
    let endpoint = transport::quic::client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        config,
        &QuicConfig::default(),
    )
    .unwrap();
    let conn = transport::quic::connect(&endpoint, addr, "localhost")
        .await
        .unwrap();
    let conn = conn.connection().clone();
    let mut control = conn.open_uni().await.unwrap();
    control
        .write_all(&proto::auth::client_control_stream())
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&web::h3_request_headers(method, "localhost", path))
        .await
        .unwrap();
    send.finish().unwrap();
    let raw = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(1 << 20))
        .await
        .unwrap()
        .unwrap();
    // HEADERS frame, then DATA frames.
    let (fields, used) = decode_response(&raw);
    let status = fields
        .iter()
        .find(|(n, _)| n == ":status")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let mut names: Vec<String> = fields
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| !n.starts_with(':'))
        .collect();
    names.sort();
    let mut data = proto::auth::DataFrameReader::default();
    (status, names, data.push(&raw[used..]).unwrap())
}

/// Decodes a response `HEADERS` frame.
fn decode_response(raw: &[u8]) -> (Vec<(String, String)>, usize) {
    web::decode_response_for_tests(raw).expect("response HEADERS")
}

#[tokio::test(flavor = "multi_thread")]
async fn c19_t1_https_without_token_gets_the_site() {
    let (addr, _, _, _) = start(true).await;
    let (status, names, body) = https(addr, "GET", "/", "").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("It works."));
    for name in [
        "server",
        "date",
        "content-type",
        "content-length",
        "alt-svc",
    ] {
        assert!(
            names.contains(&name.to_owned()),
            "{name} missing: {names:?}"
        );
    }
    // A real HTTPS client agrees.
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_ok()
    {
        let out = tokio::process::Command::new("curl")
            .args([
                "-sk",
                "--max-time",
                "5",
                &format!("https://127.0.0.1:{}/", addr.port()),
            ])
            .output()
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("It works."),
            "{out:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn c19_t2_http3_without_token_gets_the_same_site() {
    let (addr, _, _, _) = start(true).await;
    let (status, names, body) = h3(addr, "GET", "/").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("It works."));
    assert!(names.contains(&"alt-svc".to_owned()) && names.contains(&"server".to_owned()));
    let (head_status, _, head_body) = h3(addr, "HEAD", "/").await;
    assert_eq!((head_status, head_body.len()), (200, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn c19_t3_auth_path_without_token_looks_like_any_missing_page() {
    let (addr, _, _, _) = start(true).await;
    // HTTPS: the auth path, with and without an upgrade attempt, against a random path.
    let plain = https(addr, "GET", "/no-such-page", "").await;
    for extra in [
        "",
        "Connection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: Bearer nope\r\n",
    ] {
        let auth = https(addr, "GET", "/api/v2/sync", extra).await;
        assert_eq!(
            (auth.0, &auth.1, &auth.2),
            (plain.0, &plain.1, &plain.2),
            "{extra:?}"
        );
    }
    assert_eq!(plain.0, 404);
    assert_eq!(
        https(addr, "POST", "/api/v2/sync", "").await.0,
        https(addr, "POST", "/x", "").await.0
    );
    // HTTP/3: POST to the auth path without credentials, against any other missing page.
    let h3_auth = h3(addr, "POST", "/api/v2/sync").await;
    let h3_other = h3(addr, "POST", "/somewhere").await;
    assert_eq!(h3_auth, h3_other);
    let h3_missing = h3(addr, "GET", "/api/v2/sync").await;
    assert_eq!((h3_missing.0, &h3_missing.2), (plain.0, &plain.2));
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_files_reload_without_restart() {
    let dir = temp_path("x").parent().unwrap().to_path_buf();
    let write_cert = || {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
        transport::tls::spki_pin(cert.der()).unwrap()
    };
    let first = write_cert();
    let store =
        server::certs::CertStore::from_files(dir.join("cert.pem"), dir.join("key.pem")).unwrap();
    assert_eq!(store.pin(), Some(first));
    assert_eq!(store.reload(), Ok(false), "unchanged files");
    std::thread::sleep(Duration::from_millis(1100)); // mtime granularity
    let second = write_cert();
    assert_eq!(store.reload(), Ok(true));
    assert_eq!(store.pin(), Some(second));
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(dir.join("cert.pem"), "garbage").unwrap();
    assert!(store.reload().is_err());
    assert_eq!(
        store.pin(),
        Some(second),
        "a broken renewal keeps the old certificate"
    );
}

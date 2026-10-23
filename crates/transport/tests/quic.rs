//! QUIC transport between two endpoints in one process over loopback.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use quinn::Endpoint;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport::quic::{self, QuicTransport};
use transport::tls::{self, ALPN_H3, ServerVerification};
use transport::{Congestion, DatagramError, QuicConfig, Transport};

const LOOPBACK: &str = "127.0.0.1:0";

struct Pair {
    client: QuicTransport,
    server: QuicTransport,
    client_endpoint: Endpoint,
    _server_endpoint: Endpoint,
}

fn server_tls() -> (rustls::ServerConfig, [u8; 32]) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pin = tls::spki_pin(cert.der()).unwrap();
    let key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let config = tls::server_config(vec![cert.der().clone()], key, &[ALPN_H3]).unwrap();
    (config, pin)
}

async fn pair_with(
    server_config: &QuicConfig,
    client_tls: impl FnOnce([u8; 32]) -> rustls::ClientConfig,
) -> Pair {
    let (server_tls, pin) = server_tls();
    let server_endpoint =
        quic::server_endpoint(LOOPBACK.parse().unwrap(), server_tls, server_config).unwrap();
    let addr = server_endpoint.local_addr().unwrap();
    let client_endpoint = quic::client_endpoint(
        LOOPBACK.parse().unwrap(),
        client_tls(pin),
        &QuicConfig::default(),
    )
    .unwrap();
    let accept = async {
        let conn = server_endpoint.accept().await.unwrap().await.unwrap();
        QuicTransport::new(conn)
    };
    let (client, server) = tokio::join!(quic::connect(&client_endpoint, addr, "localhost"), accept);
    Pair {
        client: client.unwrap(),
        server,
        client_endpoint,
        _server_endpoint: server_endpoint,
    }
}

async fn pair() -> Pair {
    pair_with(&QuicConfig::default(), |pin| {
        tls::client_config(ServerVerification::Pin(pin), &[ALPN_H3]).unwrap()
    })
    .await
}

/// Server side: echo every stream back until FIN.
fn spawn_echo(server: QuicTransport) {
    tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = server.accept_stream().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                recv.read_to_end(&mut buf).await.unwrap();
                send.write_all(&buf).await.unwrap();
                send.shutdown().await.unwrap();
            });
        }
    });
}

async fn echo(transport: &QuicTransport, data: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = transport.open_stream().await.unwrap();
    send.write_all(data).await.unwrap();
    send.shutdown().await.unwrap();
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    back
}

#[tokio::test]
async fn c07_t1_echo_over_a_bidi_stream() {
    let p = pair().await;
    spawn_echo(p.server.clone());
    let data: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    assert_eq!(echo(&p.client, &data).await, data);
    assert_eq!(echo(&p.client, b"second stream").await, b"second stream");
    let alpn = p
        .client
        .connection()
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol);
    assert_eq!(alpn.as_deref(), Some(ALPN_H3));
}

#[tokio::test]
async fn c07_t2_datagrams_arrive_and_oversize_fails() {
    let p = pair().await;
    p.client
        .send_datagram(Bytes::from_static(b"rtp packet"))
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), p.server.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, Bytes::from_static(b"rtp packet"));

    let max = p.client.max_datagram_size().unwrap();
    // Starts at the initial MTU minus QUIC overhead; enough for a WebRTC media packet.
    assert!(max >= 1100, "max datagram {max}");
    assert_eq!(
        p.client.send_datagram(Bytes::from(vec![0; max + 1])),
        Err(DatagramError::TooLarge)
    );
    p.client.send_datagram(Bytes::from(vec![7; max])).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), p.server.recv_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.len(), max);
}

#[tokio::test]
async fn c07_t4_windows_and_congestion_come_from_config() {
    let toml = r#"
        congestion = "newreno"
        stream_receive_window = "1KiB"
        receive_window = "64KiB"
        idle_timeout = "20s"
    "#;
    let config: QuicConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.congestion, Congestion::NewReno);
    assert_eq!(config.stream_receive_window, 1024);
    assert_eq!(config.receive_window, 64 << 10);
    assert_eq!(config.idle_timeout, Duration::from_secs(20));
    assert_eq!(
        config.send_window,
        QuicConfig::default().send_window,
        "unset keeps the default"
    );
    assert!(
        toml::from_str::<QuicConfig>("congestion = \"bbr\"").is_err(),
        "BBR is not offered"
    );
    assert!(toml::from_str::<QuicConfig>("bogus = 1").is_err());

    // The server's 1 KiB stream window caps what the client may send before it reads.
    let p = pair_with(&config, |pin| {
        tls::client_config(ServerVerification::Pin(pin), &[ALPN_H3]).unwrap()
    })
    .await;
    let (mut send, _recv) = p.client.open_stream().await.unwrap();
    let mut sent = 0;
    let blocked = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            sent += send.write(&[0; 4096]).await.unwrap();
        }
    })
    .await;
    assert!(blocked.is_err(), "writes never blocked");
    assert!(sent <= 1024, "sent {sent} bytes past a 1 KiB window");
}

#[tokio::test]
async fn c07_t5_zero_rtt_is_refused() {
    // Even a client that asks for early data gets none: the server issues no 0-RTT tickets.
    let p = pair_with(&QuicConfig::default(), |pin| {
        let mut tls = tls::client_config(ServerVerification::Pin(pin), &[ALPN_H3]).unwrap();
        tls.enable_early_data = true;
        tls
    })
    .await;
    spawn_echo(p.server.clone());
    // Wait for the session ticket, then reconnect with resumption.
    assert_eq!(echo(&p.client, b"x").await, b"x");
    let addr: SocketAddr = p.client.connection().remote_address();
    let connecting = p.client_endpoint.connect(addr, "localhost").unwrap();
    assert!(connecting.into_0rtt().is_err(), "0-RTT was offered");
}

#[tokio::test]
async fn rebind_keeps_the_connection() {
    let p = pair().await;
    spawn_echo(p.server.clone());
    assert_eq!(echo(&p.client, b"before").await, b"before");
    quic::rebind(&p.client_endpoint, LOOPBACK.parse().unwrap()).unwrap();
    assert_eq!(echo(&p.client, b"after").await, b"after");
}

#[tokio::test]
async fn wrong_pin_fails_the_handshake() {
    let (server_tls, _) = server_tls();
    let server = quic::server_endpoint(
        LOOPBACK.parse().unwrap(),
        server_tls,
        &QuicConfig::default(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });
    let tls = tls::client_config(ServerVerification::Pin([0; 32]), &[ALPN_H3]).unwrap();
    let client =
        quic::client_endpoint(LOOPBACK.parse().unwrap(), tls, &QuicConfig::default()).unwrap();
    assert!(quic::connect(&client, addr, "localhost").await.is_err());
}

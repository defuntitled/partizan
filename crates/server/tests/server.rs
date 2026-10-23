//! Server end to end in one process: a test client authenticates over QUIC and proxies TCP.

mod common;

use std::net::Ipv4Addr;

use common::*;
use proto::auth::HandshakeError;
use proto::{ConnectStatus, ErrorCode, Host, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn c08_t1_connect_to_tcp_echo_both_ways() {
    let (addr, pin, _, _) = start(true).await;
    let echo = echo_server().await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let (mut send, mut recv) = open(&client, ip_target(echo), b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let writer = async {
        send.write_all(&data).await.unwrap();
        send.shutdown().await.unwrap();
    };
    let mut back = Vec::new();
    let reader = recv.read_to_end(&mut back);
    let (_, read) = tokio::join!(writer, reader);
    read.unwrap();
    assert_eq!(back, data);
}

#[tokio::test]
async fn c08_t2_domain_is_resolved_on_the_server() {
    let (addr, pin, _, _) = start(true).await;
    let echo = echo_server().await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    // The client sends the name unresolved; the server looks it up (hosts file here).
    let target = TargetAddr {
        host: Host::Domain("localhost".into()),
        port: echo.port(),
    };
    let (mut send, mut recv) = open(&client, target, b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    send.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn c08_t3_unreachable_and_refused_targets_reset_with_codes() {
    let (addr, pin, _, _) = start(true).await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let (_send, mut recv) = open(&client, ip_target(closed), b"").await;
    assert_eq!(read_result(&mut recv).await, Err(ErrorCode::TARGET_REFUSED));

    let nowhere = TargetAddr {
        host: Host::Domain("unreachable.invalid".into()),
        port: 80,
    };
    let (_send, mut recv) = open(&client, nowhere, b"").await;
    assert_eq!(
        read_result(&mut recv).await,
        Err(ErrorCode::TARGET_UNREACHABLE)
    );
}

#[tokio::test]
async fn c08_t4_internal_targets_are_not_allowed() {
    let (addr, pin, _, _) = start(false).await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let targets = [
        Host::V4(Ipv4Addr::LOCALHOST),
        Host::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Host::V4(Ipv4Addr::new(169, 254, 169, 254)),
        // A name that resolves to loopback is caught after resolution.
        Host::Domain("localhost".into()),
    ];
    for host in targets {
        let (_send, mut recv) = open(
            &client,
            TargetAddr {
                host: host.clone(),
                port: 80,
            },
            b"",
        )
        .await;
        assert_eq!(
            read_result(&mut recv).await,
            Err(ErrorCode::NOT_ALLOWED),
            "{host:?}"
        );
    }
}

#[tokio::test]
async fn c08_t5_fast_open_data_before_connect_result_arrives() {
    let (addr, pin, _, _) = start(true).await;
    let echo = echo_server().await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    // Header and payload in one write, before the result is read.
    let (mut send, mut recv) = open(&client, ip_target(echo), b"GET / HTTP/1.1\r\n\r\n").await;
    send.shutdown().await.unwrap();
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"GET / HTTP/1.1\r\n\r\n");
}

#[tokio::test]
async fn c08_t6_half_close_passes_through_both_ways() {
    let (addr, pin, _, _) = start(true).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    // Target: reads to EOF (client FIN), then answers and closes.
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        tcp.read_to_end(&mut got).await.unwrap();
        tcp.write_all(format!("got {} bytes", got.len()).as_bytes())
            .await
            .unwrap();
        tcp.shutdown().await.unwrap();
    });
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let (mut send, mut recv) = open(&client, ip_target(target), b"hello").await;
    send.shutdown().await.unwrap();
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"got 5 bytes");

    // The other way: the target closes its side first, the client keeps sending.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = tcp.into_split();
        w.write_all(b"bye").await.unwrap();
        w.shutdown().await.unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        done_tx.send(got).unwrap();
    });
    let (mut send, mut recv) = open(&client, ip_target(target), b"").await;
    assert_eq!(read_result(&mut recv).await, Ok(ConnectStatus::Ok));
    let mut back = Vec::new();
    recv.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"bye");
    send.write_all(b"still talking").await.unwrap();
    send.shutdown().await.unwrap();
    assert_eq!(done_rx.await.unwrap(), b"still talking");
}

#[tokio::test]
async fn bad_token_gets_not_found_and_reload_applies_revocation() {
    let (addr, pin, state, devices) = start(true).await;
    assert_eq!(
        connect(addr, pin, [0; 32]).await.err(),
        Some(HandshakeError::Rejected)
    );
    assert!(connect(addr, pin, TOKEN).await.is_ok());
    // C08-T7 is manual (SIGHUP); the reload it triggers is checked here.
    write_registry(&devices, true);
    assert_eq!(state.reload_registry(), Ok(1));
    assert_eq!(
        connect(addr, pin, TOKEN).await.err(),
        Some(HandshakeError::Rejected)
    );
    // A broken file keeps the old registry.
    std::fs::write(&devices, "not toml [").unwrap();
    assert!(state.reload_registry().is_err());
    assert_eq!(
        connect(addr, pin, TOKEN).await.err(),
        Some(HandshakeError::Rejected)
    );
}

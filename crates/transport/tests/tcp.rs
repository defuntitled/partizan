//! Mux transport over an in-memory pipe (TLS is the caller's business).

use std::time::{Duration, Instant};

use bytes::Bytes;
use proto::ErrorCode;
use proto::mux::Role;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use transport::tcp::MuxTransport;
use transport::{ControlChannel, Transport, TransportError};

fn pair() -> (MuxTransport, MuxTransport) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    (
        MuxTransport::new(a, Role::Client, &[]),
        MuxTransport::new(b, Role::Server, &[]),
    )
}

fn spawn_echo(server: MuxTransport) {
    tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = server.accept_stream().await {
            tokio::spawn(async move {
                let mut data = Vec::new();
                recv.read_to_end(&mut data).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.shutdown().await.unwrap();
            });
        }
    });
}

async fn echo(client: &MuxTransport, data: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = client.open_stream().await.unwrap();
    let writer = async {
        send.write_all(data).await.unwrap();
        send.shutdown().await.unwrap();
    };
    let mut back = Vec::new();
    let (_, read) = tokio::join!(writer, recv.read_to_end(&mut back));
    read.unwrap();
    back
}

#[tokio::test]
async fn streams_echo_in_parallel_without_mixing() {
    let (client, server) = pair();
    spawn_echo(server);
    let tasks: Vec<_> = (0..8u8)
        .map(|i| {
            let client = client.clone();
            tokio::spawn(async move {
                // More than the 256 KiB window, so flow control has to work.
                let data = vec![i; 600 * 1024];
                assert_eq!(echo(&client, &data).await, data, "stream {i}");
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn datagrams_and_control_messages_arrive() {
    let (client, server) = pair();
    client.send_datagram(Bytes::from_static(b"rtp")).unwrap();
    assert_eq!(
        server.recv_datagram().await.unwrap(),
        Bytes::from_static(b"rtp")
    );
    assert_eq!(client.max_datagram_size(), Some(65_507));
    assert!(client.send_datagram(Bytes::from(vec![0; 65_508])).is_err());
    ControlChannel::send(&client, b"ping".to_vec())
        .await
        .unwrap();
    assert_eq!(ControlChannel::recv(&server).await.unwrap(), b"ping");
}

#[tokio::test]
async fn resets_carry_their_code() {
    let (client, server) = pair();
    let (mut send, mut recv) = client.open_stream().await.unwrap();
    send.write_all(b"x").await.unwrap();
    let (mut s_send, _s_recv) = server.accept_stream().await.unwrap();
    s_send.reset(ErrorCode::TARGET_REFUSED);
    let mut buf = [0u8; 1];
    let err = recv.read(&mut buf).await.unwrap_err();
    assert_eq!(transport::reset_code(&err), Some(ErrorCode::TARGET_REFUSED));
}

#[tokio::test]
async fn c16_t4_datagram_does_not_wait_behind_bulk_data() {
    let (client, server) = pair();
    // The server drains a bulk stream slowly-ish while the client floods it.
    tokio::spawn({
        let server = server.clone();
        async move {
            let (_send, mut recv) = server.accept_stream().await.unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            while recv.read(&mut buf).await.unwrap_or(0) > 0 {}
        }
    });
    let (mut bulk, _recv) = client.open_stream().await.unwrap();
    tokio::spawn(async move {
        let chunk = vec![1u8; 1024 * 1024];
        while bulk.write_all(&chunk).await.is_ok() {}
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut worst = Duration::ZERO;
    for _ in 0..20 {
        let sent = Instant::now();
        client.send_datagram(Bytes::from_static(b"voice")).unwrap();
        server.recv_datagram().await.unwrap();
        worst = worst.max(sent.elapsed());
    }
    // Behind 16 KiB DATA frames, not behind the megabytes queued on the stream.
    assert!(
        worst < Duration::from_millis(50),
        "datagram waited {worst:?}"
    );
}

#[tokio::test]
async fn closing_wakes_everyone() {
    let (client, server) = pair();
    let waiter = tokio::spawn({
        let server = server.clone();
        async move { server.recv_datagram().await }
    });
    client.close(ErrorCode::NO_ERROR, b"");
    assert_eq!(client.closed().await, TransportError::ClosedLocally);
    assert!(waiter.await.unwrap().is_err());
    assert!(client.open_stream().await.is_err());
}

#[tokio::test]
async fn c16_t5_datagram_overflow_drops_old_ones_instead_of_queueing() {
    // A tiny pipe makes the writer fall behind, so the 64 KiB datagram queue overflows.
    let (a, b) = tokio::io::duplex(1024);
    let (client, server) = (
        MuxTransport::new(a, Role::Client, &[]),
        MuxTransport::new(b, Role::Server, &[]),
    );
    for i in 0..400u16 {
        let mut datagram = vec![0u8; 1000];
        datagram[..2].copy_from_slice(&i.to_be_bytes());
        client.send_datagram(Bytes::from(datagram)).unwrap();
    }
    let mut got = Vec::new();
    while let Ok(Ok(d)) =
        tokio::time::timeout(Duration::from_millis(300), server.recv_datagram()).await
    {
        got.push(u16::from_be_bytes([d[0], d[1]]));
    }
    assert!(got.len() < 400, "nothing was dropped");
    assert_eq!(got.last(), Some(&399), "the newest datagram must survive");
    assert!(got.windows(2).all(|w| w[0] < w[1]), "order kept");
}

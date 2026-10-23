//! UDP NAT on the server: datagrams through QUIC DATAGRAM frames to real UDP sockets.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use proto::auth::DataFrameReader;
use proto::control::{ControlReader, udp_close};
use proto::{ControlFrame, Host, TargetAddr, UdpDatagram};
use server::config::Limits;
use tokio::net::UdpSocket;
use transport::Transport;

fn target(addr: SocketAddr) -> TargetAddr {
    TargetAddr {
        host: Host::V4(Ipv4Addr::LOCALHOST),
        port: addr.port(),
    }
}

fn send(client: &Client, id: u64, addr: Option<TargetAddr>, payload: &[u8]) {
    let mut out = Vec::new();
    UdpDatagram {
        session_id: id,
        addr,
        payload: Bytes::copy_from_slice(payload),
    }
    .encode(&mut out)
    .unwrap();
    client.transport.send_datagram(out.into()).unwrap();
}

async fn recv(client: &Client) -> Option<UdpDatagram> {
    let raw = tokio::time::timeout(Duration::from_secs(2), client.transport.recv_datagram())
        .await
        .ok()?
        .ok()?;
    Some(UdpDatagram::decode(raw).unwrap())
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

fn limits(f: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    f(&mut limits);
    limits
}

/// Next `UdpClose` on the control channel within `timeout`.
async fn next_close(client: &mut Client, timeout: Duration) -> Option<(u64, u8)> {
    let (mut data, mut frames) = (DataFrameReader::default(), ControlReader::default());
    loop {
        match client.next_control(&mut data, &mut frames, timeout).await? {
            ControlFrame::UdpClose { session_id, reason } => return Some((session_id, reason)),
            _ => continue,
        }
    }
}

#[tokio::test]
async fn c10_t1_udp_echo_carries_the_source_address() {
    let (addr, pin, _, _) = start(true).await;
    let echo = udp_echo().await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    send(&client, 1, Some(target(echo)), b"hello udp");
    let reply = recv(&client).await.expect("echo reply");
    assert_eq!(reply.session_id, 1);
    assert_eq!(reply.addr, Some(target(echo)));
    assert_eq!(&reply.payload[..], b"hello udp");
    // Without an address the datagram goes to the last destination.
    send(&client, 1, None, b"again");
    assert_eq!(&recv(&client).await.unwrap().payload[..], b"again");
}

#[tokio::test]
async fn c10_t2_full_cone_lets_another_peer_reply() {
    let (addr, pin, _, _) = start(true).await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send(&client, 7, Some(target(a.local_addr().unwrap())), b"to a");
    let mut buf = [0u8; 64];
    let (_, mapped) = a.recv_from(&mut buf).await.unwrap();
    // Peer B, never contacted, writes to the same mapping (an ICE candidate from elsewhere).
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    b.send_to(b"from b", mapped).await.unwrap();
    let reply = recv(&client).await.expect("datagram from b");
    assert_eq!(reply.session_id, 7);
    assert_eq!(reply.addr, Some(target(b.local_addr().unwrap())));
    assert_eq!(&reply.payload[..], b"from b");
}

#[tokio::test]
async fn c10_t3_idle_sessions_close_and_port_53_sooner() {
    let limits = limits(|l| {
        l.udp_idle_timeout = Duration::from_millis(1500);
        l.udp_dns_idle_timeout = Duration::from_millis(200);
    });
    let (addr, pin, _, _) = start_with(true, limits).await;
    let echo = udp_echo().await;
    let mut client = connect(addr, pin, TOKEN).await.unwrap();
    send(&client, 1, Some(target(echo)), b"x");
    recv(&client).await.unwrap();
    let dns = TargetAddr {
        host: Host::V4(Ipv4Addr::LOCALHOST),
        port: 53,
    };
    send(&client, 2, Some(dns), b"query");
    // The DNS session goes first, the other after its longer timeout.
    assert_eq!(
        next_close(&mut client, Duration::from_secs(1)).await,
        Some((2, udp_close::IDLE))
    );
    assert_eq!(
        next_close(&mut client, Duration::from_secs(3)).await,
        Some((1, udp_close::IDLE))
    );
}

#[tokio::test]
async fn c10_t4_sessions_over_the_limit_are_refused() {
    let (addr, pin, _, _) = start_with(true, limits(|l| l.udp_sessions_per_device = 2)).await;
    let echo = udp_echo().await;
    let mut client = connect(addr, pin, TOKEN).await.unwrap();
    for id in [1, 2] {
        send(&client, id, Some(target(echo)), b"in");
        assert_eq!(recv(&client).await.unwrap().session_id, id);
    }
    send(&client, 3, Some(target(echo)), b"over");
    assert_eq!(
        next_close(&mut client, Duration::from_secs(2)).await,
        Some((3, udp_close::LIMIT))
    );
    assert!(
        recv(&client).await.is_none(),
        "no reply for a refused session"
    );
}

#[tokio::test]
async fn c10_t5_udp_close_frees_the_session() {
    let (addr, pin, _, _) = start_with(true, limits(|l| l.udp_sessions_per_device = 1)).await;
    let echo = udp_echo().await;
    let mut client = connect(addr, pin, TOKEN).await.unwrap();
    send(&client, 1, Some(target(echo)), b"first");
    recv(&client).await.unwrap();
    client
        .send_control(ControlFrame::UdpClose {
            session_id: 1,
            reason: udp_close::NORMAL,
        })
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The slot is free again, and id 1 without an address is now unknown.
    send(&client, 1, None, b"stale");
    send(&client, 2, Some(target(echo)), b"second");
    let reply = recv(&client).await.expect("reply on the freed slot");
    assert_eq!((reply.session_id, &reply.payload[..]), (2, &b"second"[..]));
}

#[tokio::test]
async fn c10_t6_oversize_replies_are_dropped_and_counted() {
    let (addr, pin, state, _) = start(true).await;
    let client = connect(addr, pin, TOKEN).await.unwrap();
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send(&client, 1, Some(target(a.local_addr().unwrap())), b"hi");
    let mut buf = [0u8; 64];
    let (_, mapped) = a.recv_from(&mut buf).await.unwrap();
    let max = client.transport.max_datagram_size().unwrap();
    a.send_to(&vec![0u8; max + 100], mapped).await.unwrap();
    a.send_to(b"small", mapped).await.unwrap();
    let reply = recv(&client).await.expect("the small one still arrives");
    assert_eq!(&reply.payload[..], b"small");
    assert_eq!(state.metrics.udp_oversize_drops.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn denied_destination_gets_udp_close() {
    let (addr, pin, _, _) = start(true).await;
    let mut client = connect(addr, pin, TOKEN).await.unwrap();
    let internal = TargetAddr {
        host: Host::V4(Ipv4Addr::new(10, 0, 0, 1)),
        port: 9,
    };
    send(&client, 4, Some(internal), b"x");
    assert_eq!(
        next_close(&mut client, Duration::from_secs(2)).await,
        Some((4, udp_close::NOT_ALLOWED))
    );
}

#[tokio::test]
async fn udp_limit_is_shared_by_the_device_connections() {
    let (addr, pin, _, _) = start_with(true, limits(|l| l.udp_sessions_per_device = 1)).await;
    let echo = udp_echo().await;
    let first = connect(addr, pin, TOKEN).await.unwrap();
    send(&first, 1, Some(target(echo)), b"in");
    recv(&first).await.unwrap();
    // A second connection of the same device has no slot left.
    let mut second = connect(addr, pin, TOKEN).await.unwrap();
    send(&second, 1, Some(target(echo)), b"over");
    assert_eq!(
        next_close(&mut second, Duration::from_secs(2)).await,
        Some((1, udp_close::LIMIT))
    );
    // When the first connection ends, its slot comes back.
    first.transport.connection().close(0u32.into(), b"");
    drop(first);
    tokio::time::sleep(Duration::from_millis(500)).await;
    send(&second, 2, Some(target(echo)), b"now");
    assert_eq!(recv(&second).await.map(|d| d.session_id), Some(2));
}

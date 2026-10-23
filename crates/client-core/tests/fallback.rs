//! QUIC → TCP+TLS fallback, with UDP "blocked" by a relay in front of the server.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::*;
use proto::auth::TransportMode;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// TCP always passes; UDP passes only while `udp_open` is set (otherwise it is swallowed, as
/// by a firewall that drops UDP/443).
struct Relay {
    addr: SocketAddr,
    udp_open: Arc<AtomicBool>,
    udp_seen: Arc<AtomicU64>,
    tcp_seen: Arc<AtomicU64>,
}

async fn relay(server: SocketAddr, udp_open: bool) -> Relay {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = Arc::new(UdpSocket::bind(addr).await.unwrap());
    let (open, udp_seen, tcp_seen) = (
        Arc::new(AtomicBool::new(udp_open)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let seen = tcp_seen.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = tcp.accept().await {
            seen.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut upstream = TcpStream::connect(server).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    let (gate, seen) = (open.clone(), udp_seen.clone());
    tokio::spawn(async move {
        let upstreams: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Arc::default();
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = udp.recv_from(&mut buf).await {
            seen.fetch_add(1, Ordering::Relaxed);
            if !gate.load(Ordering::Relaxed) {
                continue;
            }
            let mut map = upstreams.lock().await;
            let up = match map.get(&from) {
                Some(up) => up.clone(),
                None => {
                    let up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    up.connect(server).await.unwrap();
                    let (up2, udp2, gate2) = (up.clone(), udp.clone(), gate.clone());
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65_535];
                        while let Ok(n) = up2.recv(&mut buf).await {
                            if gate2.load(Ordering::Relaxed) {
                                let _ = udp2.send_to(&buf[..n], from).await;
                            }
                        }
                    });
                    map.insert(from, up.clone());
                    up
                }
            };
            drop(map);
            let _ = up.send(&buf[..n]).await;
        }
    });
    Relay {
        addr,
        udp_open: open,
        udp_seen,
        tcp_seen,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn c17_t1_blocked_udp_falls_back_to_tls_within_five_seconds() {
    let f = fixture();
    let (server, _, _endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;
    let relay = relay(server, false).await;
    let engine = engine_with(
        &f,
        relay.addr,
        TransportMode::Auto,
        client_core::FALLBACK_MEMORY,
    );
    let started = Instant::now();
    engine.start();
    assert!(
        eventually(Duration::from_secs(6), async || engine
            .status()
            .await
            .transport
            == Some("tls"))
        .await
    );
    let took = started.elapsed();
    assert!(took <= Duration::from_secs(5), "fallback took {took:?}");
    assert!(
        relay.udp_seen.load(Ordering::Relaxed) > 0,
        "QUIC was tried first"
    );
    let echo = tcp_echo().await;
    assert!(engine.open_tcp(target(echo), true).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn c17_t2_background_probe_returns_to_quic_once_udp_is_back() {
    let f = fixture();
    let (server, _, _endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;
    let relay = relay(server, false).await;
    // Short memory so the test sees the probe.
    let engine = engine_with(&f, relay.addr, TransportMode::Auto, Duration::from_secs(1));
    engine.start();
    assert!(
        eventually(Duration::from_secs(6), async || engine
            .status()
            .await
            .transport
            == Some("tls"))
        .await
    );
    relay.udp_open.store(true, Ordering::Relaxed);
    assert!(
        eventually(Duration::from_secs(10), async || engine
            .status()
            .await
            .transport
            == Some("quic"))
        .await,
        "never switched back to QUIC"
    );
    let echo = tcp_echo().await;
    assert!(engine.open_tcp(target(echo), true).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn c17_t3_fixed_modes_do_not_switch() {
    let f = fixture();
    let (server, _, _endpoint) = start_server(&f, "127.0.0.1:0".parse().unwrap()).await;

    // quic with UDP blocked: no fallback, no TCP connection at all.
    let relay_q = relay(server, false).await;
    let quic = engine_with(
        &f,
        relay_q.addr,
        TransportMode::Quic,
        client_core::FALLBACK_MEMORY,
    );
    quic.start();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(quic.status().await.transport, None);
    assert_eq!(
        relay_q.tcp_seen.load(Ordering::Relaxed),
        0,
        "quic mode went to TCP"
    );

    // tls with UDP open: QUIC is never tried.
    let relay_t = relay(server, true).await;
    let tls = engine_with(
        &f,
        relay_t.addr,
        TransportMode::Tls,
        client_core::FALLBACK_MEMORY,
    );
    tls.start();
    assert!(
        eventually(Duration::from_secs(5), async || tls
            .status()
            .await
            .transport
            == Some("tls"))
        .await
    );
    assert_eq!(
        relay_t.udp_seen.load(Ordering::Relaxed),
        0,
        "tls mode sent UDP"
    );
}

//! Benchmark endpoints behind `partizan.bench` (see `proto::bench`). Authenticated devices
//! only, and only with `[bench] enabled = true`.

use std::net::SocketAddr;

use bytes::BytesMut;
use proto::{ConnectResult, ConnectStatus, ErrorCode, Host, TargetAddr, bench};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use transport::{RecvHalf, SendHalf};

/// True if `addr` names a benchmark endpoint.
pub fn is_bench(addr: &TargetAddr) -> bool {
    matches!(&addr.host, Host::Domain(name) if name.eq_ignore_ascii_case(bench::HOST))
}

/// Serves one benchmark stream.
pub async fn serve(port: u16, early: BytesMut, mut send: SendHalf, mut recv: RecvHalf) {
    if !matches!(port, bench::DOWNLOAD | bench::UPLOAD | bench::ECHO) {
        send.reset(ErrorCode::NOT_ALLOWED);
        recv.stop(ErrorCode::NOT_ALLOWED);
        return;
    }
    let mut header = Vec::new();
    let ok = ConnectResult {
        status: ConnectStatus::Ok,
        padding: 0,
    };
    ok.encode(&mut header)
        .expect("ConnectResult without padding always encodes");
    if send.write_all(&header).await.is_err() {
        return;
    }
    match port {
        bench::DOWNLOAD => {
            let chunk = vec![0u8; 64 * 1024];
            while send.write_all(&chunk).await.is_ok() {}
        }
        bench::UPLOAD => {
            let mut total = early.len() as u64;
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = recv.read(&mut buf).await {
                if n == 0 {
                    let _ = send.write_all(&total.to_be_bytes()).await;
                    let _ = send.shutdown().await;
                    return;
                }
                total += n as u64;
            }
        }
        _ => {
            if send.write_all(&early).await.is_ok() {
                let _ = tokio::io::copy(&mut recv, &mut send).await;
                let _ = send.shutdown().await;
            }
        }
    }
}

/// UDP echo the NAT forwards `partizan.bench:3` to; returns its local address.
pub async fn spawn_udp_echo() -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    Ok(addr)
}

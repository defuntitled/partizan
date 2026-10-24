//! L4 masquerade: never terminate TLS for an unrecognized ClientHello.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proto::tls_hello::{self, ClientHello, HelloError, MAX_CLIENT_HELLO};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_IDLE: Duration = Duration::from_secs(60);
const MAX_UDP_FLOWS: usize = 1024;
const UDP_QUEUE: usize = 32;
// Bound record framing too (including pathological one-byte handshake fragments).
const MAX_PREFIX: usize = MAX_CLIENT_HELLO * 6;

/// Bytes inspected before a routing decision; the original record framing is preserved.
pub(crate) struct Prefix {
    pub(crate) bytes: Vec<u8>,
    pub(crate) hello: Option<ClientHello>,
}

/// Reads at most one bounded ClientHello. Malformed, oversized and slow probes also go to
/// the upstream: they must never elicit our own TLS certificate or TLS alert.
pub(crate) async fn read_prefix(stream: &mut TcpStream) -> io::Result<Prefix> {
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(HELLO_TIMEOUT, async {
        let mut chunk = [0; 2048];
        loop {
            match tls_hello::parse(&bytes) {
                Ok(hello) => return Ok::<_, io::Error>(Some(hello)),
                Err(HelloError::NotClientHello) => return Ok(None),
                Err(HelloError::Incomplete) => {}
            }
            if bytes.len() == MAX_PREFIX {
                return Ok(None);
            }
            let room = chunk.len().min(MAX_PREFIX - bytes.len());
            let n = stream.read(&mut chunk[..room]).await?;
            if n == 0 {
                return Ok(None);
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
    })
    .await;
    let hello = match result {
        Ok(result) => result?,
        Err(_) => None,
    };
    Ok(Prefix { bytes, hello })
}

/// Forwards the inspected prefix exactly once, then copies both directions, including
/// TCP half closes. The upstream is configured by the administrator, never by client SNI.
pub(crate) async fn forward_tcp(
    mut stream: TcpStream,
    upstream: SocketAddr,
    prefix: &[u8],
) -> io::Result<()> {
    let mut remote = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream)).await??;
    remote.set_nodelay(true)?;
    tokio::time::timeout(CONNECT_TIMEOUT, remote.write_all(prefix)).await??;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

/// Blind UDP relay. One connected upstream socket per source prevents cross-client replies
/// and rejects datagrams from other upstream addresses. Idle flows and queues are bounded.
pub(crate) async fn forward_udp(socket: UdpSocket, upstream: SocketAddr) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut flows: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut buf = vec![0; 65_535];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (n, source) = received?;
                if flows.get(&source).is_some_and(mpsc::Sender::is_closed) {
                    flows.remove(&source);
                }
                if !flows.contains_key(&source) {
                    flows.retain(|_, sender| !sender.is_closed());
                    if flows.len() == MAX_UDP_FLOWS {
                        continue;
                    }
                    let (tx, rx) = mpsc::channel(UDP_QUEUE);
                    flows.insert(source, tx);
                    let socket = socket.clone();
                    tasks.spawn(async move {
                        let _ = udp_flow(socket, source, upstream, rx).await;
                    });
                }
                if let Some(tx) = flows.get(&source) {
                    let _ = tx.try_send(buf[..n].to_vec());
                }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {
                flows.retain(|_, sender| !sender.is_closed());
            }
        }
    }
}

async fn udp_flow(
    listener: Arc<UdpSocket>,
    source: SocketAddr,
    upstream: SocketAddr,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let bind = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    let mut buf = vec![0; 65_535];
    loop {
        tokio::time::timeout(UDP_IDLE, async {
            tokio::select! {
                packet = packets.recv() => {
                    let packet = packet.ok_or(io::ErrorKind::UnexpectedEof)?;
                    socket.send(&packet).await?;
                }
                received = socket.recv(&mut buf) => {
                    listener.send_to(&buf[..received?], source).await?;
                }
            }
            Ok::<_, io::Error>(())
        })
        .await??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Server;
    use crate::config::Config;
    use tokio::net::TcpListener;
    use transport::tls::{self, ALPN_HTTP11, ServerVerification};

    async fn server(upstream: SocketAddr) -> (Server, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "partizan-c23-{}-{}",
            std::process::id(),
            upstream.port()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let devices = dir.join("devices.toml");
        std::fs::write(&devices, "").unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
            [server]
            listen = "127.0.0.1:0"
            auth_path = "/auth"
            devices = "{}"
            [tls]
            mode = "self-signed"
            [masquerade]
            mode = "passthrough"
            sni = "localhost"
        "#,
            devices.display()
        ))
        .unwrap();
        let mut server = Server::bind(config).await.unwrap();
        // Keep the production destination fixed at sni:443; tests use an ephemeral upstream.
        server.passthrough.as_mut().unwrap().1 = upstream;
        (server, dir)
    }

    #[tokio::test]
    async fn c23_t1_t2_tls_and_content_come_from_upstream() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let leaf = cert.cert.der().clone();
        let pin = transport::tls::spki_pin(&leaf).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        let config = tls::server_config(vec![leaf], key, &[ALPN_HTTP11]).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let (server, dir) = server(upstream.local_addr().unwrap()).await;
        let addr = server.local_addr().unwrap();
        let endpoint = server.endpoint();
        let run = tokio::spawn(server.run());
        let site = tokio::spawn(async move {
            let (tcp, _) = upstream.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                tls.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            tls.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream",
            )
            .await
            .unwrap();
            tls.shutdown().await.unwrap();
        });
        let client = tls::client_config(ServerVerification::Pin(pin), &[ALPN_HTTP11]).unwrap();
        let mut tls = tokio::time::timeout(
            Duration::from_secs(5),
            transport::tcp::connect_tls(addr, "localhost", client),
        )
        .await
        .unwrap()
        .unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.ends_with(b"\r\n\r\nupstream"));
        site.await.unwrap();
        endpoint.close(0u32.into(), b"");
        run.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn c23_t3_prefix_and_half_close_are_preserved() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (server, dir) = server(upstream.local_addr().unwrap()).await;
        let addr = server.local_addr().unwrap();
        let endpoint = server.endpoint();
        let run = tokio::spawn(server.run());
        // Non-TLS probes, including bytes read past the routing decision, pass unchanged.
        let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let site = tokio::spawn(async move {
            let (mut tcp, _) = upstream.accept().await.unwrap();
            let mut received = Vec::new();
            tcp.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
            tcp.write_all(b"after client FIN").await.unwrap();
            tcp.shutdown().await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"after client FIN");
        site.await.unwrap();
        endpoint.close(0u32.into(), b"");
        run.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn c23_t4_udp_is_blind_and_sources_are_isolated() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (server, dir) = server(upstream.local_addr().unwrap()).await;
        let addr = server.local_addr().unwrap();
        let endpoint = server.endpoint();
        let run = tokio::spawn(server.run());
        let site = tokio::spawn(async move {
            let mut buf = [0; 1024];
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
                peers.push(peer);
                upstream.send_to(&buf[..n], peer).await.unwrap();
            }
            assert_ne!(peers[0], peers[1]);
        });
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for (socket, payload) in [(&a, b"not QUIC A"), (&b, b"not QUIC B")] {
            socket.send_to(payload, addr).await.unwrap();
            let mut buf = [0; 100];
            let (n, peer) =
                tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(peer, addr);
            assert_eq!(&buf[..n], payload);
        }
        site.await.unwrap();
        endpoint.close(0u32.into(), b"");
        run.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}

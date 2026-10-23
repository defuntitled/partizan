//! One proxied TCP connection: `Connect` header, dial, `ConnectResult`, then bytes both ways
//! with half-close.

use std::time::Duration;

use bytes::BytesMut;
use proto::{Connect, ConnectResult, ConnectStatus, DecodeError, ErrorCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use transport::{RecvHalf, SendHalf};

use crate::State;
use crate::dial::dial;

/// Longest `Connect` header: type, 255-byte domain, port, padding.
const MAX_HEADER: usize = 2048;
/// Copy buffer per direction.
const COPY_BUFFER: usize = 64 * 1024;
/// Time allowed for the header to arrive.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves one stream until both directions are closed, or until `session_closed` resolves:
/// a dead session must not leave target sockets open.
pub async fn handle_stream(
    send: SendHalf,
    recv: RecvHalf,
    state: &State,
    session_closed: impl Future<Output = ()>,
) {
    tokio::select! {
        () = serve(send, recv, state) => {}
        () = session_closed => {}
    }
}

async fn serve(mut send: SendHalf, mut recv: RecvHalf, state: &State) {
    let header = tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut recv)).await;
    let (connect, early) = match header {
        Ok(Ok(Some(header))) => header,
        Ok(Ok(None)) => return, // Closed before a header: nothing to do.
        Ok(Err(code)) => {
            send.reset(code);
            recv.stop(code);
            return;
        }
        Err(_) => {
            send.reset(ErrorCode::PROTOCOL_ERROR);
            recv.stop(ErrorCode::PROTOCOL_ERROR);
            return;
        }
    };
    if state.bench_udp.is_some() && crate::bench::is_bench(&connect.addr) {
        crate::bench::serve(connect.addr.port, early, send, recv).await;
        return;
    }
    let tcp = match dial(&connect.addr, &state.resolver, &state.egress).await {
        Ok(tcp) => tcp,
        Err(e) => {
            tracing::debug!(target_addr = ?connect.addr, error = %e, "dial failed");
            send.reset(e.code());
            recv.stop(e.code());
            return;
        }
    };
    tracing::debug!(target_addr = ?connect.addr, "connected");
    let mut header = Vec::with_capacity(4);
    let ok = ConnectResult {
        status: ConnectStatus::Ok,
        padding: 0,
    };
    ok.encode(&mut header)
        .expect("ConnectResult without padding always encodes");
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let up = async {
        // Fast-open bytes that arrived with the header go first.
        tcp_write.write_all(&early).await?;
        let mut recv = BufReader::with_capacity(COPY_BUFFER, &mut recv);
        tokio::io::copy_buf(&mut recv, &mut tcp_write).await?;
        tcp_write.shutdown().await
    };
    let down = async {
        send.write_all(&header).await?;
        let mut tcp_read = BufReader::with_capacity(COPY_BUFFER, &mut tcp_read);
        tokio::io::copy_buf(&mut tcp_read, &mut send).await?;
        send.shutdown().await
    };
    // A broken direction ends both: a half that waits on an idle peer would leak.
    let failed = tokio::try_join!(up, down).is_err();
    if failed {
        send.reset(ErrorCode::NO_ERROR);
        recv.stop(ErrorCode::NO_ERROR);
    }
}

/// Reads until a full `Connect` header; returns it and any bytes after it, `None` on a clean
/// close before any header, or the code to reset with.
async fn read_header(recv: &mut RecvHalf) -> Result<Option<(Connect, BytesMut)>, ErrorCode> {
    let mut buf = BytesMut::with_capacity(512);
    loop {
        match Connect::decode(&buf) {
            Ok((connect, used)) => {
                let early = buf.split_off(used);
                return Ok(Some((connect, early)));
            }
            Err(DecodeError::Incomplete) if buf.len() < MAX_HEADER => {}
            Err(_) => return Err(ErrorCode::PROTOCOL_ERROR),
        }
        let mut chunk = [0u8; 1024];
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(|_| ErrorCode::NO_ERROR)?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(ErrorCode::PROTOCOL_ERROR)
            };
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

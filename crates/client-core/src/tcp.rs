//! Proxied TCP: one tunnel stream per connection, `Connect` header first.

use proto::{Connect, ConnectResult, ConnectStatus, DecodeError, ErrorCode, TargetAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use transport::{RecvHalf, SendHalf, Transport};

use crate::session::{Engine, EngineError};

/// Byte stream of the local application side.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// A TCP connection from the traffic source, to be carried to `dst`.
pub struct TcpRequest {
    /// Destination; a domain name stays unresolved and is resolved by the server.
    pub dst: TargetAddr,
    /// Local side of the connection.
    pub io: Box<dyn AsyncReadWrite>,
}

/// Why a tunnel stream could not be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// No session.
    #[error(transparent)]
    Session(#[from] EngineError),
    /// Server reset the stream: target failure or policy.
    #[error("target failed with code {0:?}")]
    Reset(ErrorCode),
    /// Server answered with a non-success status.
    #[error("target failed with status {0:?}")]
    Status(ConnectStatus),
    /// Stream ended or broke before an answer.
    #[error("stream closed")]
    Closed,
}

impl ConnectError {
    /// SOCKS5 `REP` for this failure.
    pub fn socks_reply(&self) -> u8 {
        match self {
            Self::Reset(code) => match *code {
                ErrorCode::NOT_ALLOWED => 0x02,
                ErrorCode::TARGET_UNREACHABLE => 0x04,
                ErrorCode::TARGET_REFUSED => 0x05,
                ErrorCode::TARGET_TIMEOUT => 0x06,
                _ => 0x01,
            },
            Self::Status(status) => *status as u8,
            Self::Session(_) | Self::Closed => 0x01,
        }
    }
}

impl Engine {
    /// Opens a tunnel stream to `dst`. With `wait_result`, returns only after the server's
    /// `ConnectResult`; otherwise at once (fast open), and the result header is still the first
    /// thing on the returned receive half.
    pub async fn open_tcp(
        &self,
        dst: TargetAddr,
        wait_result: bool,
    ) -> Result<(SendHalf, RecvHalf), ConnectError> {
        let session = self.session().await?;
        let (mut send, mut recv) = session
            .transport
            .open_stream()
            .await
            .map_err(|_| ConnectError::Closed)?;
        let mut header = Vec::with_capacity(32);
        Connect {
            addr: dst,
            padding: 0,
        }
        .encode(&mut header)
        .map_err(|_| ConnectError::Status(ConnectStatus::AddrTypeNotSupported))?;
        send.write_all(&header)
            .await
            .map_err(|_| ConnectError::Closed)?;
        if wait_result {
            read_result(&mut recv).await?;
        }
        Ok((send, recv))
    }

    /// Carries `request` until both directions close. Fast open: local bytes flow before the
    /// server confirms; if the target fails, the local connection is dropped.
    pub async fn handle_tcp(&self, request: TcpRequest) {
        let dst = request.dst.clone();
        match self.open_tcp(request.dst, false).await {
            Ok((send, recv)) => relay(request.io, send, recv, true).await,
            Err(e) => log::debug!("connect to {dst:?} failed: {e}"),
        }
    }
}

/// Copies a local connection and a tunnel stream both ways with half-close. With
/// `result_pending` the `ConnectResult` header is read off the stream first.
pub async fn relay(
    io: Box<dyn AsyncReadWrite>,
    mut send: SendHalf,
    mut recv: RecvHalf,
    result_pending: bool,
) {
    let (mut local_read, mut local_write) = tokio::io::split(io);
    let up = async {
        tokio::io::copy(&mut local_read, &mut send).await?;
        send.shutdown().await
    };
    let down = async {
        if result_pending {
            read_result(&mut recv)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        tokio::io::copy(&mut recv, &mut local_write).await?;
        local_write.shutdown().await
    };
    // A failed direction ends the whole connection: dropping the halves resets the stream.
    if let Err(e) = tokio::try_join!(up, down) {
        log::debug!("tunnel stream ended: {e}");
    }
}

/// Reads and checks the `ConnectResult` header, byte by byte so no data after it is consumed.
pub(crate) async fn read_result(recv: &mut RecvHalf) -> Result<(), ConnectError> {
    let mut buf = Vec::with_capacity(8);
    loop {
        match ConnectResult::decode(&buf) {
            Ok((result, _)) if result.status == ConnectStatus::Ok => return Ok(()),
            Ok((result, _)) => return Err(ConnectError::Status(result.status)),
            Err(DecodeError::Incomplete) => {}
            Err(_) => return Err(ConnectError::Closed),
        }
        let mut byte = [0u8; 1];
        match recv.read(&mut byte).await {
            Ok(1) => buf.push(byte[0]),
            Ok(_) => return Err(ConnectError::Closed),
            Err(e) => {
                return Err(
                    transport::reset_code(&e).map_or(ConnectError::Closed, ConnectError::Reset)
                );
            }
        }
    }
}

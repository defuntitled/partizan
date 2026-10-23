//! TCP+TLS transport: one TLS connection carrying the `proto` mux.
//!
//! A reader task feeds received bytes to the mux, a writer task sends what it produces; stream
//! handles lock the shared state and park on wakers. Datagrams and control messages ride in
//! mux `DATAGRAM` / `CONTROL` frames, `CONTROL` and `DATAGRAM` ahead of stream data.

use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;
use bytes::Bytes;
use proto::ErrorCode;
use proto::mux::{Event, MAX_DATAGRAM, Mux, MuxError, Read, Role};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, watch};
use tokio_rustls::rustls::pki_types::ServerName;

use crate::{
    ControlChannel, DatagramError, RecvHalf, RecvStream, SendHalf, SendStream, Transport,
    TransportError, TransportStats,
};

/// Incoming datagrams and control messages buffered before new ones are dropped.
const INBOX: usize = 1024;
/// Bytes gathered per write to the TLS stream.
const WRITE_BATCH: usize = 64 * 1024;

/// A peer reset this mux stream with `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("stream reset by peer with code {0:?}")]
pub struct StreamReset(pub ErrorCode);

struct State {
    mux: Mux,
    readers: HashMap<u64, Waker>,
    writers: HashMap<u64, Waker>,
    incoming: VecDeque<u64>,
    accept_waker: Option<Waker>,
    datagrams: VecDeque<Bytes>,
    datagram_waker: Option<Waker>,
    control: VecDeque<Bytes>,
    control_waker: Option<Waker>,
    /// Codes of streams the peer reset, kept until the local handles go.
    resets: HashMap<u64, ErrorCode>,
    /// Live handles per stream (send and receive half).
    handles: HashMap<u64, u8>,
    error: Option<TransportError>,
    closing: bool,
    bytes_sent: u64,
    bytes_received: u64,
}

struct Shared {
    state: Mutex<State>,
    transmit: Notify,
    closed: watch::Sender<Option<TransportError>>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Marks the connection dead and wakes everyone waiting on it.
    fn fail(&self, error: TransportError) {
        let mut guard = self.lock();
        // Reborrow so the fields can be drained side by side.
        let st = &mut *guard;
        if st.error.is_none() {
            st.error = Some(error.clone());
        }
        let wakers: Vec<Waker> = st
            .readers
            .drain()
            .chain(st.writers.drain())
            .map(|(_, w)| w)
            .chain(st.accept_waker.take())
            .chain(st.datagram_waker.take())
            .chain(st.control_waker.take())
            .collect();
        drop(guard);
        wakers.into_iter().for_each(Waker::wake);
        self.closed.send_replace(Some(error));
        self.transmit.notify_one();
    }
}

/// Wakes whoever a mux event concerns.
fn dispatch(st: &mut State) {
    while let Some(event) = st.mux.poll_event() {
        match event {
            Event::StreamOpened(id) => {
                st.incoming.push_back(id);
                if let Some(w) = st.accept_waker.take() {
                    w.wake();
                }
            }
            Event::Readable(id) => {
                if let Some(w) = st.readers.remove(&id) {
                    w.wake();
                }
            }
            Event::Writable(id) => {
                if let Some(w) = st.writers.remove(&id) {
                    w.wake();
                }
            }
            Event::Reset { id, code } => {
                st.resets.insert(id, code);
                for w in [st.readers.remove(&id), st.writers.remove(&id)]
                    .into_iter()
                    .flatten()
                {
                    w.wake();
                }
            }
            Event::Datagram(datagram) => {
                if st.datagrams.len() < INBOX {
                    st.datagrams.push_back(datagram);
                }
                if let Some(w) = st.datagram_waker.take() {
                    w.wake();
                }
            }
            Event::Control(message) => {
                if st.control.len() < INBOX {
                    st.control.push_back(message);
                }
                if let Some(w) = st.control_waker.take() {
                    w.wake();
                }
            }
        }
    }
}

/// [`Transport`] over one TLS connection with the mux.
#[derive(Clone)]
pub struct MuxTransport {
    shared: Arc<Shared>,
}

impl MuxTransport {
    /// Runs the mux over `io`, which already carried the auth exchange; `leftover` is what
    /// followed the auth response.
    pub fn new<S>(io: S, role: Role, leftover: &[u8]) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                mux: Mux::new(role),
                readers: HashMap::new(),
                writers: HashMap::new(),
                incoming: VecDeque::new(),
                accept_waker: None,
                datagrams: VecDeque::new(),
                datagram_waker: None,
                control: VecDeque::new(),
                control_waker: None,
                resets: HashMap::new(),
                handles: HashMap::new(),
                error: None,
                closing: false,
                bytes_sent: 0,
                bytes_received: 0,
            }),
            transmit: Notify::new(),
            closed: watch::Sender::new(None),
        });
        let (read, write) = tokio::io::split(io);
        if !leftover.is_empty() {
            let mut st = shared.lock();
            if st.mux.handle_input(leftover).is_err() {
                st.error = Some(TransportError::Lost("protocol error".into()));
            }
            dispatch(&mut st);
        }
        tokio::spawn(read_loop(read, shared.clone()));
        tokio::spawn(write_loop(write, shared.clone()));
        Self { shared }
    }

    fn stream(&self, id: u64) -> (SendHalf, RecvHalf) {
        self.shared.lock().handles.insert(id, 2);
        let send = MuxStream {
            id,
            shared: self.shared.clone(),
        };
        let recv = MuxStream {
            id,
            shared: self.shared.clone(),
        };
        (Box::new(send), Box::new(recv))
    }

    /// Sends one control message (an encoded control frame).
    pub fn send_control(&self, message: Bytes) -> Result<(), TransportError> {
        let mut st = self.shared.lock();
        if let Some(e) = &st.error {
            return Err(e.clone());
        }
        st.mux
            .send_control(message)
            .map_err(|e| TransportError::Lost(e.to_string()))?;
        drop(st);
        self.shared.transmit.notify_one();
        Ok(())
    }

    /// Next control message; `None` once the connection is gone.
    pub async fn recv_control(&self) -> Option<Bytes> {
        poll_fn(|cx| {
            let mut st = self.shared.lock();
            if let Some(message) = st.control.pop_front() {
                return Poll::Ready(Some(message));
            }
            if st.error.is_some() {
                return Poll::Ready(None);
            }
            st.control_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

async fn read_loop<R: AsyncRead + Unpin>(mut read: R, shared: Arc<Shared>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match read.read(&mut buf).await {
            Ok(0) => {
                shared.fail(TransportError::Lost("connection closed by peer".into()));
                return;
            }
            Ok(n) => n,
            Err(e) => {
                shared.fail(TransportError::Lost(e.to_string()));
                return;
            }
        };
        let mut st = shared.lock();
        if st.error.is_some() {
            return;
        }
        st.bytes_received += n as u64;
        let result = st.mux.handle_input(&buf[..n]);
        dispatch(&mut st);
        drop(st);
        if let Err(e) = result {
            shared.fail(TransportError::Lost(e.to_string()));
            return;
        }
        // Reading may have queued WINDOW_UPDATEs or RSTs.
        shared.transmit.notify_one();
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut write: W, shared: Arc<Shared>) {
    let mut out = Vec::with_capacity(WRITE_BATCH);
    loop {
        let stop = {
            let mut st = shared.lock();
            while out.len() < WRITE_BATCH && st.mux.poll_transmit(&mut out) {}
            dispatch(&mut st);
            // On close, what is queued still goes out, then the TLS close_notify.
            out.is_empty() && (st.closing || st.error.is_some())
        };
        if stop {
            let _ = write.shutdown().await;
            return;
        }
        if out.is_empty() {
            shared.transmit.notified().await;
            continue;
        }
        if let Err(e) = async {
            write.write_all(&out).await?;
            write.flush().await
        }
        .await
        {
            shared.fail(TransportError::Lost(e.to_string()));
            return;
        }
        shared.lock().bytes_sent += out.len() as u64;
        out.clear();
    }
}

#[async_trait]
impl Transport for MuxTransport {
    async fn open_stream(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        let id = {
            let mut st = self.shared.lock();
            if let Some(e) = &st.error {
                return Err(e.clone());
            }
            st.mux
                .open_stream()
                .map_err(|e| TransportError::Lost(e.to_string()))?
        };
        self.shared.transmit.notify_one();
        Ok(self.stream(id))
    }

    async fn accept_stream(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        let id = poll_fn(|cx| {
            let mut st = self.shared.lock();
            if let Some(id) = st.incoming.pop_front() {
                return Poll::Ready(Ok(id));
            }
            if let Some(e) = &st.error {
                return Poll::Ready(Err(e.clone()));
            }
            st.accept_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await?;
        Ok(self.stream(id))
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), DatagramError> {
        if data.len() > MAX_DATAGRAM {
            return Err(DatagramError::TooLarge);
        }
        let mut st = self.shared.lock();
        if st.error.is_some() {
            return Err(DatagramError::Closed);
        }
        st.mux
            .send_datagram(data)
            .map_err(|_| DatagramError::TooLarge)?;
        drop(st);
        self.shared.transmit.notify_one();
        Ok(())
    }

    async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        poll_fn(|cx| {
            let mut st = self.shared.lock();
            if let Some(datagram) = st.datagrams.pop_front() {
                return Poll::Ready(Ok(datagram));
            }
            if let Some(e) = &st.error {
                return Poll::Ready(Err(e.clone()));
            }
            st.datagram_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    fn max_datagram_size(&self) -> Option<usize> {
        Some(MAX_DATAGRAM)
    }

    fn stats(&self) -> TransportStats {
        let st = self.shared.lock();
        TransportStats {
            bytes_sent: st.bytes_sent,
            bytes_received: st.bytes_received,
            ..TransportStats::default()
        }
    }

    fn close(&self, _code: ErrorCode, _reason: &[u8]) {
        // TCP carries no application close code; a GoAway goes first where it matters.
        self.shared.lock().closing = true;
        self.shared.fail(TransportError::ClosedLocally);
    }

    async fn closed(&self) -> TransportError {
        let mut rx = self.shared.closed.subscribe();
        match rx.wait_for(Option::is_some).await {
            Ok(error) => error.clone().unwrap_or(TransportError::ClosedLocally),
            Err(_) => TransportError::ClosedLocally,
        }
    }
}

/// One half of a mux stream.
struct MuxStream {
    id: u64,
    shared: Arc<Shared>,
}

impl MuxStream {
    fn error(&self, st: &State) -> io::Error {
        if let Some(code) = st.resets.get(&self.id) {
            return io::Error::new(io::ErrorKind::ConnectionReset, StreamReset(*code));
        }
        match &st.error {
            Some(e) => io::Error::new(io::ErrorKind::ConnectionAborted, e.clone()),
            None => io::Error::from(io::ErrorKind::BrokenPipe),
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut st = self.shared.lock();
        match st.mux.read(self.id, buf.remaining()) {
            Ok(Read::Data(data)) => {
                buf.put_slice(&data);
                drop(st);
                self.shared.transmit.notify_one();
                Poll::Ready(Ok(()))
            }
            Ok(Read::Finished) => Poll::Ready(Ok(())),
            Ok(Read::Blocked) if st.error.is_some() => Poll::Ready(Err(self.error(&st))),
            Ok(Read::Blocked) => {
                st.readers.insert(self.id, cx.waker().clone());
                Poll::Pending
            }
            // Gone: reset by the peer, or fully closed and read.
            Err(_) if st.resets.contains_key(&self.id) || st.error.is_some() => {
                Poll::Ready(Err(self.error(&st)))
            }
            Err(_) => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.shared.lock();
        if st.error.is_some() {
            return Poll::Ready(Err(self.error(&st)));
        }
        match st.mux.write(self.id, data) {
            Ok(0) if !data.is_empty() => {
                st.writers.insert(self.id, cx.waker().clone());
                Poll::Pending
            }
            Ok(n) => {
                drop(st);
                self.shared.transmit.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(_) => Poll::Ready(Err(self.error(&st))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.shared.lock();
        match st.mux.finish(self.id) {
            Ok(()) => {
                drop(st);
                self.shared.transmit.notify_one();
                Poll::Ready(Ok(()))
            }
            Err(MuxError::UnknownStream(_)) if !st.resets.contains_key(&self.id) => {
                Poll::Ready(Ok(()))
            }
            Err(_) => Poll::Ready(Err(self.error(&st))),
        }
    }
}

impl SendStream for MuxStream {
    fn reset(&mut self, code: ErrorCode) {
        let _ = self.shared.lock().mux.reset(self.id, code);
        self.shared.transmit.notify_one();
    }
}

impl RecvStream for MuxStream {
    fn stop(&mut self, code: ErrorCode) {
        // The mux has no STOP_SENDING: a reset ends both directions.
        let _ = self.shared.lock().mux.reset(self.id, code);
        self.shared.transmit.notify_one();
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let mut st = self.shared.lock();
        // Like quinn: a dropped half closes its direction gracefully; errors call reset first.
        // Which half this is does not matter: finish and close_read are both idempotent.
        let left = st.handles.get_mut(&self.id).map(|n| {
            *n -= 1;
            *n
        });
        if left == Some(0) {
            st.handles.remove(&self.id);
            st.resets.remove(&self.id);
            st.readers.remove(&self.id);
            st.writers.remove(&self.id);
            let _ = st.mux.finish(self.id);
            let _ = st.mux.close_read(self.id);
            drop(st);
            self.shared.transmit.notify_one();
        }
    }
}

/// Control channel over mux `CONTROL` frames.
#[async_trait]
impl ControlChannel for MuxTransport {
    async fn send(&self, frame: Vec<u8>) -> Result<(), TransportError> {
        self.send_control(frame.into())
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        self.recv_control().await.map(|b| b.to_vec())
    }
}

/// TLS over TCP to `addr`, presenting `server_name`.
pub async fn connect_tls(
    addr: SocketAddr,
    server_name: &str,
    tls: rustls::ClientConfig,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
}

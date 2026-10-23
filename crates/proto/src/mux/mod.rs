//! Stream multiplexer for the TCP+TLS transport, sans-io.
//!
//! Feed received bytes to [`Mux::handle_input`], send what [`Mux::poll_transmit`] produces and
//! drain [`Mux::poll_event`] after every input. Stream data, datagrams and control messages are
//! opaque bytes: the first bytes of a stream are its `Connect` header, exactly as on a QUIC
//! stream.
//!
//! Memory per connection is bounded: received stream data by the window, queued stream data by
//! [`SEND_BUFFER`], both times [`MAX_STREAMS`] per side; datagrams by [`DATAGRAM_QUEUE`].
//! A stream keeps its slot while it holds unread data. Received payloads are copied out of the
//! input buffer, so a peer cannot pin it.
//!
//! An `OPEN` may be empty if [`Mux::poll_transmit`] runs between [`Mux::open_stream`] and the
//! first [`Mux::write`]; write the `Connect` header right after opening to avoid that.

mod frame;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{DecodeError, ErrorCode, control, varint};
use frame::FrameType;

/// Initial per-stream flow-control window; both sides must use the same value.
pub const INITIAL_WINDOW: u64 = 256 * 1024;
/// Accepted but unsent bytes per stream, however much window the peer grants.
pub const SEND_BUFFER: u64 = 256 * 1024;
/// Concurrent streams each side may open.
pub const MAX_STREAMS: usize = 1024;
/// Datagram send queue in bytes; older datagrams are dropped beyond it.
pub const DATAGRAM_QUEUE: usize = 64 * 1024;
/// Control messages waiting to be sent.
pub const CONTROL_QUEUE: usize = 64;
/// Largest `DATA` / `OPEN` payload, so a call's datagram never waits behind a big frame.
pub const MAX_DATA: usize = 16 * 1024;
/// Largest datagram payload over TCP+TLS.
pub const MAX_DATAGRAM: usize = 65_507;
/// Largest `CONTROL` payload: one control frame with its type and length.
pub const MAX_CONTROL: usize = control::MAX_CONTROL_BODY + 16;

/// Which side of the connection this is; decides stream id parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Opens odd stream ids.
    Client,
    /// Opens even stream ids.
    Server,
}

/// Mux error. [`MuxError::Protocol`] and [`MuxError::Decode`] are fatal: close the connection
/// with [`MuxError::code`]; the others reject a single call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MuxError {
    /// Peer violated the protocol.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// Peer sent an undecodable frame header.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// No such open stream.
    #[error("unknown stream {0}")]
    UnknownStream(u64),
    /// Local concurrent stream limit reached.
    #[error("stream limit reached")]
    StreamLimit,
    /// `write` after `finish`.
    #[error("stream {0} already finished")]
    StreamFinished(u64),
    /// Datagram is larger than [`MAX_DATAGRAM`].
    #[error("datagram of {0} bytes is too large")]
    DatagramTooLarge(usize),
    /// Control message is larger than [`MAX_CONTROL`].
    #[error("control message of {0} bytes is too large")]
    ControlTooLarge(usize),
    /// [`CONTROL_QUEUE`] messages are already waiting.
    #[error("control queue is full")]
    ControlQueueFull,
    /// Error code is above the varint range.
    #[error("error code {0} does not fit in a varint")]
    InvalidCode(u64),
}

impl MuxError {
    /// Connection close code for fatal errors, `None` for errors that reject a single call.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Protocol(_) | Self::Decode(_) => Some(ErrorCode::PROTOCOL_ERROR),
            _ => None,
        }
    }
}

/// Something the application should react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Peer opened a stream.
    StreamOpened(u64),
    /// Data arrived on an empty stream, or FIN arrived; [`Mux::read`] until `Blocked`.
    Readable(u64),
    /// Window grew after a short [`Mux::write`]; write again.
    Writable(u64),
    /// Peer reset the stream; it is gone.
    Reset {
        /// Stream id.
        id: u64,
        /// Code from the `RST`.
        code: ErrorCode,
    },
    /// Datagram from the peer, still encoded.
    Datagram(Bytes),
    /// Control message from the peer, still encoded; the receiver checks it is one frame.
    Control(Bytes),
}

/// Result of [`Mux::read`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// Next chunk of stream data, never empty.
    Data(Bytes),
    /// Nothing buffered yet; wait for [`Event::Readable`].
    Blocked,
    /// Peer finished sending and all data has been read.
    Finished,
}

#[derive(Debug, Default)]
struct Stream {
    /// `OPEN` has been sent or received.
    opened: bool,
    /// Holds a slot in the stream limit; released on wire events, not on reads.
    counted: bool,
    /// Accepted but unsent bytes.
    send_queue: BytesMut,
    /// Bytes the peer still allows us to send, queued ones included.
    send_credit: u64,
    fin_queued: bool,
    fin_sent: bool,
    /// Last `write` was cut short by the window.
    blocked: bool,
    in_round_robin: bool,

    recv_buf: BytesMut,
    /// Total bytes received and allowed to be received.
    recv_total: u64,
    recv_limit: u64,
    /// Bytes read by the application since the last `WINDOW_UPDATE`.
    unacked: u64,
    fin_received: bool,
    fin_delivered: bool,
    /// The application stopped reading; data is discarded and credited back.
    read_closed: bool,
}

impl Stream {
    fn new(opened: bool) -> Self {
        Self {
            opened,
            counted: true,
            send_credit: INITIAL_WINDOW,
            recv_limit: INITIAL_WINDOW,
            ..Self::default()
        }
    }

    fn has_pending_send(&self) -> bool {
        !self.opened || !self.send_queue.is_empty() || (self.fin_queued && !self.fin_sent)
    }
}

/// Frames that bypass the round-robin.
#[derive(Debug)]
enum Urgent {
    Rst(u64, ErrorCode),
    /// `RST STREAM_LIMIT` for a peer stream over the limit.
    Refuse(u64),
    WindowUpdate(u64, u64),
}

/// Multiplexer state for one TCP+TLS connection.
#[derive(Debug)]
pub struct Mux {
    role: Role,
    streams: HashMap<u64, Stream>,
    local_streams: usize,
    peer_streams: usize,
    next_local_id: u64,
    /// Highest local stream id whose `OPEN` went out, 0 if none.
    max_sent_open: u64,
    /// Highest stream id the peer has opened, 0 if none.
    max_peer_id: u64,
    /// `RST STREAM_LIMIT` frames queued for refused peer streams.
    refused_pending: usize,

    control_queue: VecDeque<Bytes>,
    datagram_queue: VecDeque<Bytes>,
    datagram_bytes: usize,
    datagram_drops: u64,
    urgent: VecDeque<Urgent>,
    round_robin: VecDeque<u64>,

    recv_buf: BytesMut,
    events: VecDeque<Event>,
    failed: Option<MuxError>,
}

impl Mux {
    /// Creates the multiplexer for one side of a connection.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            streams: HashMap::new(),
            local_streams: 0,
            peer_streams: 0,
            next_local_id: match role {
                Role::Client => 1,
                Role::Server => 2,
            },
            max_sent_open: 0,
            max_peer_id: 0,
            refused_pending: 0,
            control_queue: VecDeque::new(),
            datagram_queue: VecDeque::new(),
            datagram_bytes: 0,
            datagram_drops: 0,
            urgent: VecDeque::new(),
            round_robin: VecDeque::new(),
            recv_buf: BytesMut::new(),
            events: VecDeque::new(),
            failed: None,
        }
    }

    /// Opens a stream. `OPEN` is queued at once so they leave in id order; data written before
    /// the next [`Mux::poll_transmit`] rides in it.
    pub fn open_stream(&mut self) -> Result<u64, MuxError> {
        if self.local_streams >= MAX_STREAMS || self.next_local_id > varint::MAX {
            return Err(MuxError::StreamLimit);
        }
        let id = self.next_local_id;
        self.next_local_id += 2;
        self.streams.insert(id, Stream::new(false));
        self.local_streams += 1;
        self.schedule(id);
        Ok(id)
    }

    /// Queues as much of `data` as the window and [`SEND_BUFFER`] allow; returns how much was
    /// taken. A short count means wait for [`Event::Writable`].
    pub fn write(&mut self, id: u64, data: &[u8]) -> Result<usize, MuxError> {
        let s = self
            .streams
            .get_mut(&id)
            .ok_or(MuxError::UnknownStream(id))?;
        if s.fin_queued {
            return Err(MuxError::StreamFinished(id));
        }
        let limit = s.send_credit.min(SEND_BUFFER);
        let room = limit.saturating_sub(s.send_queue.len() as u64) as usize;
        let n = data.len().min(room);
        s.send_queue.extend_from_slice(&data[..n]);
        s.blocked = n < data.len();
        self.schedule(id);
        Ok(n)
    }

    /// Closes the sending side after the queued data (`FIN`).
    pub fn finish(&mut self, id: u64) -> Result<(), MuxError> {
        let s = self
            .streams
            .get_mut(&id)
            .ok_or(MuxError::UnknownStream(id))?;
        s.fin_queued = true;
        self.schedule(id);
        Ok(())
    }

    /// Aborts the stream in both directions (`RST`) and forgets it.
    pub fn reset(&mut self, id: u64, code: ErrorCode) -> Result<(), MuxError> {
        if code.0 > varint::MAX {
            return Err(MuxError::InvalidCode(code.0));
        }
        let s = self.remove(id).ok_or(MuxError::UnknownStream(id))?;
        // A stream the peer never saw needs no RST.
        if s.opened {
            self.urgent.push_back(Urgent::Rst(id, code));
        }
        Ok(())
    }

    /// Stops reading the stream: buffered and later data are discarded and credited back, and
    /// the stream goes away once FIN has passed both ways. Sending is unaffected.
    pub fn close_read(&mut self, id: u64) -> Result<(), MuxError> {
        let s = self
            .streams
            .get_mut(&id)
            .ok_or(MuxError::UnknownStream(id))?;
        s.read_closed = true;
        s.unacked += s.recv_buf.len() as u64;
        s.recv_buf.clear();
        if s.fin_received {
            s.fin_delivered = true;
        } else {
            Self::credit(&mut self.urgent, id, s);
        }
        self.release_slot_if_closed(id);
        self.remove_if_done(id);
        Ok(())
    }

    /// Queues a `WINDOW_UPDATE` once half the window has been consumed.
    fn credit(urgent: &mut VecDeque<Urgent>, id: u64, s: &mut Stream) {
        if !s.fin_received && s.unacked >= INITIAL_WINDOW / 2 {
            s.recv_limit += s.unacked;
            urgent.push_back(Urgent::WindowUpdate(id, s.unacked));
            s.unacked = 0;
        }
    }

    /// Reads up to `max` (at least 1) bytes of stream data.
    pub fn read(&mut self, id: u64, max: usize) -> Result<Read, MuxError> {
        let s = self
            .streams
            .get_mut(&id)
            .ok_or(MuxError::UnknownStream(id))?;
        if !s.recv_buf.is_empty() {
            let n = s.recv_buf.len().min(max.max(1));
            let data = s.recv_buf.split_to(n).freeze();
            s.unacked += n as u64;
            if !s.fin_received && s.unacked >= INITIAL_WINDOW / 2 {
                s.recv_limit += s.unacked;
                self.urgent.push_back(Urgent::WindowUpdate(id, s.unacked));
                s.unacked = 0;
            }
            self.release_slot_if_closed(id);
            return Ok(Read::Data(data));
        }
        if !s.fin_received {
            return Ok(Read::Blocked);
        }
        s.fin_delivered = true;
        self.remove_if_done(id);
        Ok(Read::Finished)
    }

    /// Queues a datagram, dropping the oldest ones beyond [`DATAGRAM_QUEUE`] bytes.
    pub fn send_datagram(&mut self, datagram: Bytes) -> Result<(), MuxError> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(MuxError::DatagramTooLarge(datagram.len()));
        }
        self.datagram_bytes += datagram.len();
        self.datagram_queue.push_back(datagram);
        while self.datagram_bytes > DATAGRAM_QUEUE {
            let old = self.datagram_queue.pop_front().unwrap_or_default();
            self.datagram_bytes -= old.len();
            self.datagram_drops += 1;
        }
        Ok(())
    }

    /// Queues one encoded control frame.
    pub fn send_control(&mut self, message: Bytes) -> Result<(), MuxError> {
        if message.len() > MAX_CONTROL {
            return Err(MuxError::ControlTooLarge(message.len()));
        }
        if self.control_queue.len() >= CONTROL_QUEUE {
            return Err(MuxError::ControlQueueFull);
        }
        self.control_queue.push_back(message);
        Ok(())
    }

    /// Datagrams dropped from the send queue so far.
    pub fn datagram_drops(&self) -> u64 {
        self.datagram_drops
    }

    /// Streams still tracked, both sides, including closed ones with unread data.
    pub fn open_streams(&self) -> usize {
        self.streams.len()
    }

    /// Next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Appends the next frame to `out`, which must be growable (`Vec`, `BytesMut`); returns
    /// `false` when there is nothing to send.
    pub fn poll_transmit(&mut self, out: &mut impl BufMut) -> bool {
        if let Some(message) = self.control_queue.pop_front() {
            frame::encode(0, FrameType::Control, &message, out);
            return true;
        }
        if let Some(datagram) = self.datagram_queue.pop_front() {
            self.datagram_bytes -= datagram.len();
            frame::encode(0, FrameType::Datagram, &datagram, out);
            return true;
        }
        if let Some(urgent) = self.urgent.pop_front() {
            let (id, ty, value) = match urgent {
                Urgent::Rst(id, code) => (id, FrameType::Rst, code.0),
                Urgent::Refuse(id) => {
                    self.refused_pending -= 1;
                    (id, FrameType::Rst, ErrorCode::STREAM_LIMIT.0)
                }
                Urgent::WindowUpdate(id, increment) => (id, FrameType::WindowUpdate, increment),
            };
            let mut payload = Vec::with_capacity(8);
            frame::put_varint(value, &mut payload);
            frame::encode(id, ty, &payload, out);
            return true;
        }
        while let Some(id) = self.round_robin.pop_front() {
            let Some(s) = self.streams.get_mut(&id) else {
                continue; // Reset while queued.
            };
            s.in_round_robin = false;
            if !s.opened {
                let chunk = s.send_queue.split_to(s.send_queue.len().min(MAX_DATA));
                s.send_credit -= chunk.len() as u64;
                s.opened = true;
                self.max_sent_open = id;
                frame::encode(id, FrameType::Open, &chunk, out);
            } else if !s.send_queue.is_empty() {
                let chunk = s.send_queue.split_to(s.send_queue.len().min(MAX_DATA));
                s.send_credit -= chunk.len() as u64;
                frame::encode(id, FrameType::Data, &chunk, out);
                // Sending frees room only when SEND_BUFFER, not the window, cut the write short.
                let room = s.send_credit.min(SEND_BUFFER) > s.send_queue.len() as u64;
                if s.blocked && room {
                    s.blocked = false;
                    self.events.push_back(Event::Writable(id));
                }
            } else if s.fin_queued && !s.fin_sent {
                s.fin_sent = true;
                frame::encode(id, FrameType::Fin, &[], out);
            } else {
                continue;
            }
            if s.has_pending_send() {
                s.in_round_robin = true;
                self.round_robin.push_back(id);
            }
            self.release_slot_if_closed(id);
            self.remove_if_done(id);
            return true;
        }
        false
    }

    /// Processes received bytes. A returned error is fatal and repeats on later calls.
    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), MuxError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        self.recv_buf.extend_from_slice(data);
        let result = self.process_frames();
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }

    fn process_frames(&mut self) -> Result<(), MuxError> {
        while let Some((header, header_len)) = frame::decode(&self.recv_buf)? {
            if self.recv_buf.len() < header_len + header.len {
                break;
            }
            self.recv_buf.advance(header_len);
            // Handlers copy what they keep, so this view is dropped right after.
            let payload = self.recv_buf.split_to(header.len);
            self.on_frame(header, &payload)?;
        }
        Ok(())
    }

    fn on_frame(&mut self, header: frame::Header, payload: &[u8]) -> Result<(), MuxError> {
        let id = header.stream_id;
        match header.ty {
            FrameType::Datagram | FrameType::Control if id != 0 => {
                Err(MuxError::Protocol("DATAGRAM or CONTROL off stream 0"))
            }
            FrameType::Datagram => {
                let datagram = Bytes::copy_from_slice(payload);
                self.events.push_back(Event::Datagram(datagram));
                Ok(())
            }
            FrameType::Control => {
                let message = Bytes::copy_from_slice(payload);
                self.events.push_back(Event::Control(message));
                Ok(())
            }
            _ if id == 0 => Err(MuxError::Protocol("stream frame on stream 0")),
            FrameType::Open => self.on_open(id, payload),
            ty => self.on_stream_frame(id, ty, payload),
        }
    }

    fn on_open(&mut self, id: u64, payload: &[u8]) -> Result<(), MuxError> {
        if self.is_local(id) || id <= self.max_peer_id {
            return Err(MuxError::Protocol("OPEN with a used or wrong-parity id"));
        }
        self.max_peer_id = id;
        if self.peer_streams >= MAX_STREAMS {
            // A well-behaved opener has at most MAX_STREAMS streams it counts as free but we still
            // hold, so more outstanding refusals than that mean a flood.
            if self.refused_pending >= MAX_STREAMS {
                return Err(MuxError::Protocol("too many refused streams"));
            }
            self.refused_pending += 1;
            self.urgent.push_back(Urgent::Refuse(id));
            return Ok(());
        }
        self.streams.insert(id, Stream::new(true));
        self.peer_streams += 1;
        self.events.push_back(Event::StreamOpened(id));
        self.on_stream_frame(id, FrameType::Data, payload)
    }

    fn on_stream_frame(&mut self, id: u64, ty: FrameType, payload: &[u8]) -> Result<(), MuxError> {
        if !self.was_opened(id) {
            return Err(MuxError::Protocol("frame for a stream never opened"));
        }
        let Some(s) = self.streams.get_mut(&id) else {
            return Ok(()); // Late frame for a stream that is already gone.
        };
        match ty {
            FrameType::Data => {
                if s.fin_received {
                    return Err(MuxError::Protocol("DATA after FIN"));
                }
                s.recv_total += payload.len() as u64;
                if s.recv_total > s.recv_limit {
                    return Err(MuxError::Protocol("flow control window exceeded"));
                }
                if s.read_closed {
                    // Nobody reads: give the window straight back so the peer is not stalled.
                    s.unacked += payload.len() as u64;
                    Self::credit(&mut self.urgent, id, s);
                } else if !payload.is_empty() {
                    if s.recv_buf.is_empty() {
                        self.events.push_back(Event::Readable(id));
                    }
                    s.recv_buf.extend_from_slice(payload);
                }
            }
            FrameType::Fin => {
                if s.fin_received {
                    return Err(MuxError::Protocol("duplicate FIN"));
                }
                s.fin_received = true;
                if s.read_closed {
                    s.fin_delivered = true;
                } else {
                    self.events.push_back(Event::Readable(id));
                }
                self.release_slot_if_closed(id);
                self.remove_if_done(id);
            }
            FrameType::Rst => {
                let code = ErrorCode(frame::varint_payload(payload, "malformed RST")?);
                self.remove(id);
                self.events.push_back(Event::Reset { id, code });
            }
            FrameType::WindowUpdate => {
                let increment = frame::varint_payload(payload, "malformed WINDOW_UPDATE")?;
                s.send_credit = s
                    .send_credit
                    .checked_add(increment)
                    .filter(|&credit| credit <= varint::MAX)
                    .ok_or(MuxError::Protocol("window overflow"))?;
                if s.blocked {
                    s.blocked = false;
                    self.events.push_back(Event::Writable(id));
                }
            }
            // Dispatched in `on_frame`; never reach here.
            FrameType::Open | FrameType::Datagram | FrameType::Control => {
                return Err(MuxError::Protocol("misrouted frame"));
            }
        }
        Ok(())
    }

    fn is_local(&self, id: u64) -> bool {
        (id % 2 == 1) == (self.role == Role::Client)
    }

    /// The stream's `OPEN` has crossed the wire in either direction.
    fn was_opened(&self, id: u64) -> bool {
        if self.is_local(id) {
            id <= self.max_sent_open
        } else {
            id <= self.max_peer_id
        }
    }

    fn schedule(&mut self, id: u64) {
        if let Some(s) = self.streams.get_mut(&id)
            && !s.in_round_robin
            && s.has_pending_send()
        {
            s.in_round_robin = true;
            self.round_robin.push_back(id);
        }
    }

    /// Frees the stream-limit slot once FIN has gone both ways and no unread data is left,
    /// without waiting for the app to read `Finished`.
    ///
    /// The opener frees its slot only after sending FIN and receiving the peer's, and its next
    /// `OPEN` follows its FIN on the wire, so a receiver that has read all data has freed the
    /// slot by then. On reset both sides free at once; the RST precedes any later `OPEN` because
    /// urgent frames always go before the round-robin. A receiver still holding unread data
    /// keeps the slot and may refuse the next `OPEN`: that is backpressure.
    fn release_slot_if_closed(&mut self, id: u64) {
        let local = self.is_local(id);
        if let Some(s) = self.streams.get_mut(&id)
            && s.counted
            && s.fin_sent
            && s.fin_received
            && s.recv_buf.is_empty()
        {
            s.counted = false;
            if local {
                self.local_streams -= 1;
            } else {
                self.peer_streams -= 1;
            }
        }
    }

    fn remove_if_done(&mut self, id: u64) {
        if self
            .streams
            .get(&id)
            .is_some_and(|s| s.fin_sent && s.fin_delivered)
        {
            self.remove(id);
        }
    }

    fn remove(&mut self, id: u64) -> Option<Stream> {
        let s = self.streams.remove(&id)?;
        if s.counted {
            if self.is_local(id) {
                self.local_streams -= 1;
            } else {
                self.peer_streams -= 1;
            }
        }
        Some(s)
    }
}

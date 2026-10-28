//! The stack task: packets from the interface into `smoltcp` and UDP flows, and back.
//!
//! One task owns the interface, all sockets and the flow table. Each TCP connection is a
//! `smoltcp` socket listening on the exact destination of its SYN (AnyIP mode), bridged to the
//! handler through an in-memory duplex stream. UDP bypasses `smoltcp`: datagrams are parsed and
//! built directly, one flow per source address and path.
//!
//! Split tunneling picks the handler: a connection at its SYN, a datagram by its destination.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use client_core::TcpRequest;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep};

use crate::diagnostics::{Counters, Diagnostics};
use crate::engine::target;
use crate::packet::{self, Inbound};
use crate::split::{Path, Rules, Split};
use crate::{Config, Handler, PacketDevice, UdpPacket};

/// Packets read, or replies taken, per wakeup before the task yields.
const BATCH: usize = 64;
/// Packets waiting for the interface before `smoltcp` holds back and replies are dropped.
const OUT_QUEUE: usize = 1024;
/// In-memory buffer between a connection's socket and its handler, each direction.
const DUPLEX_BUFFER: usize = 16 * 1024;
/// Outgoing datagrams queued per UDP flow before new ones are dropped.
const FLOW_QUEUE: usize = 256;
/// Replies from all flows of one path queued for the interface.
const REPLY_QUEUE: usize = 1024;
/// A connection whose peer stops answering while data is outstanding is aborted after this.
const TCP_TIMEOUT: SmolDuration = SmolDuration::from_secs(120);
/// How often idle UDP flows are looked for.
const SWEEP: Duration = Duration::from_secs(5);
/// How often metrics go to the log while profiling.
const REPORT: Duration = Duration::from_secs(10);
/// Largest IP packet the interface can hand over.
const MAX_PACKET: usize = 65_535;

/// Runs the stack until the interface ends (a read returns 0 bytes) or fails. New
/// connections and flows go to `tunnel` or `direct` as `split` decides; `split` and
/// `diagnostics` may be changed while it runs.
pub async fn run<D: PacketDevice, T: Handler, R: Handler>(
    device: D,
    tunnel: T,
    direct: R,
    split: Arc<Split>,
    config: Config,
    diagnostics: Arc<Diagnostics>,
) -> io::Result<()> {
    let mut stack = Stack::new(device, tunnel, direct, split, config, diagnostics);
    std::future::poll_fn(|cx| stack.poll(cx)).await
}

struct Stack<D, T, R> {
    device: D,
    tunnel: T,
    direct: R,
    split: Arc<Split>,
    /// Rules for the current iteration.
    rules: Arc<Rules>,
    config: Config,
    diag: Arc<Diagnostics>,
    /// Profiling flag for the current iteration.
    profiling: bool,
    iface: Interface,
    sockets: SocketSet<'static>,
    phy: Phy,
    tcp: HashMap<SocketHandle, Conn>,
    /// `(source, destination)` of every connection, so a retransmitted SYN opens nothing new.
    tuples: HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    udp: HashMap<(SocketAddr, Path), Flow>,
    tunnel_replies: Replies,
    direct_replies: Replies,
    buf: Vec<u8>,
    epoch: Instant,
    timer: Pin<Box<Sleep>>,
    next_sweep: Instant,
    next_report: Instant,
}

/// Where the flows of one path send their replies.
struct Replies {
    tx: mpsc::Sender<UdpPacket>,
    rx: mpsc::Receiver<UdpPacket>,
}

impl Replies {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(REPLY_QUEUE);
        Self { tx, rx }
    }
}

/// `smoltcp`'s view of the interface: TCP packets queued for it, everything queued for the fd.
struct Phy {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct PhyRx(Vec<u8>);
struct PhyTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for PhyRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for PhyTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for Phy {
    type RxToken<'a> = PhyRx;
    type TxToken<'a> = PhyTx<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(PhyRx, PhyTx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((PhyRx(packet), PhyTx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<PhyTx<'_>> {
        (self.tx.len() < OUT_QUEUE).then_some(PhyTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// One TCP connection: its socket's handle is the key in `Stack::tcp`.
struct Conn {
    /// Our end of the stream handed to the handler.
    io: DuplexStream,
    src: SocketAddr,
    dst: SocketAddr,
    path: Path,
    /// The handshake with the app completed.
    established: bool,
    /// The app's FIN was passed on to the handler.
    io_shut: bool,
    /// The handler finished writing; FIN sent to the app.
    io_eof: bool,
}

/// One step of moving bytes between a socket and its stream.
enum Step {
    Moved(usize),
    Eof,
    Pending,
    Failed,
}

impl Conn {
    /// Moves what can be moved both ways; `true` if anything changed.
    fn pump(&mut self, socket: &mut tcp::Socket<'_>, cx: &mut Context<'_>, split: &Split) -> bool {
        use tcp::State;
        if !matches!(
            socket.state(),
            State::Closed | State::Listen | State::SynSent | State::SynReceived
        ) {
            self.established = true;
        }
        let mut progress = false;
        // App → handler.
        while socket.can_recv() {
            let io = &mut self.io;
            let step = socket.recv(|buf| match Pin::new(io).poll_write(cx, buf) {
                Poll::Ready(Ok(0)) | Poll::Pending => (0, Step::Pending),
                Poll::Ready(Ok(n)) => (n, Step::Moved(n)),
                Poll::Ready(Err(_)) => (0, Step::Failed),
            });
            match step {
                Ok(Step::Moved(n)) => {
                    split.sent(self.path, n);
                    progress = true;
                }
                Ok(Step::Pending) => break,
                _ => {
                    socket.abort();
                    return true;
                }
            }
        }
        // The app's FIN, once everything before it was handed over.
        if self.established
            && !self.io_shut
            && !socket.may_recv()
            && Pin::new(&mut self.io).poll_shutdown(cx).is_ready()
        {
            self.io_shut = true;
            progress = true;
        }
        // Handler → app.
        while !self.io_eof && socket.can_send() {
            let io = &mut self.io;
            let step = socket.send(|buf| {
                let mut read = ReadBuf::new(buf);
                match Pin::new(io).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) if read.filled().is_empty() => (0, Step::Eof),
                    Poll::Ready(Ok(())) => {
                        let n = read.filled().len();
                        (n, Step::Moved(n))
                    }
                    Poll::Ready(Err(_)) => (0, Step::Failed),
                    Poll::Pending => (0, Step::Pending),
                }
            });
            match step {
                Ok(Step::Moved(n)) => {
                    split.received(self.path, n);
                    progress = true;
                }
                Ok(Step::Pending) => break,
                Ok(Step::Eof) => {
                    self.io_eof = true;
                    socket.close();
                    progress = true;
                }
                Ok(Step::Failed) | Err(_) => {
                    socket.abort();
                    return true;
                }
            }
        }
        progress
    }
}

struct Flow {
    tx: mpsc::Sender<UdpPacket>,
    last: Instant,
}

impl<D: PacketDevice, T: Handler, R: Handler> Stack<D, T, R> {
    fn new(
        device: D,
        tunnel: T,
        direct: R,
        split: Arc<Split>,
        config: Config,
        diag: Arc<Diagnostics>,
    ) -> Self {
        let mut phy = Phy {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: config.mtu,
        };
        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        // Seeds initial sequence numbers and ports.
        iface_config.random_seed = RandomState::new().hash_one(0u8);
        let epoch = Instant::now();
        let mut iface = Interface::new(iface_config, &mut phy, SmolInstant::ZERO);
        // AnyIP: every destination is local, sockets listen on the exact address of each SYN.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            // Placeholders: an interface needs addresses of both families to speak them.
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Addr::new(198, 18, 0, 1)),
                32,
            ));
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                128,
            ));
        });
        Self {
            device,
            tunnel,
            direct,
            rules: split.rules(),
            split,
            config,
            diag,
            profiling: false,
            iface,
            sockets: SocketSet::new(Vec::new()),
            phy,
            tcp: HashMap::new(),
            tuples: HashMap::new(),
            udp: HashMap::new(),
            tunnel_replies: Replies::new(),
            direct_replies: Replies::new(),
            buf: vec![0u8; MAX_PACKET],
            epoch,
            timer: Box::pin(tokio::time::sleep_until(epoch)),
            next_sweep: epoch + SWEEP,
            next_report: epoch + REPORT,
        }
    }

    fn smol_now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    fn count(&self, counter: fn(&Counters) -> &std::sync::atomic::AtomicU64, n: u64) {
        if self.profiling {
            Counters::add(counter(&self.diag.counters), n);
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.profiling = self.diag.profiling();
        self.rules = self.split.rules();
        let started = self.profiling.then(std::time::Instant::now);
        let mut io_time = Duration::ZERO;
        let mut packets = 0u64;
        let mut more = false;

        // Interface → stack.
        let mut buf = std::mem::take(&mut self.buf);
        for i in 0..BATCH {
            let t = self.profiling.then(std::time::Instant::now);
            let read = self.device.poll_recv(cx, &mut buf);
            if let Some(t) = t {
                io_time += t.elapsed();
            }
            match read {
                Poll::Pending => break,
                // A TUN never yields an empty packet: the fd was closed.
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(n)) => {
                    packets += 1;
                    self.count(|c| &c.packets_in, 1);
                    self.count(|c| &c.bytes_in, n as u64);
                    self.inbound(&buf[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
            more |= i == BATCH - 1;
        }
        self.buf = buf;

        // Replies from UDP flows.
        for path in [Path::Tunnel, Path::Direct] {
            for i in 0..BATCH {
                let replies = match path {
                    Path::Tunnel => &mut self.tunnel_replies.rx,
                    Path::Direct => &mut self.direct_replies.rx,
                };
                match replies.poll_recv(cx) {
                    Poll::Ready(Some(reply)) => self.reply(path, reply),
                    _ => break,
                }
                more |= i == BATCH - 1;
            }
        }

        // TCP: let `smoltcp` process and emit, move bytes, repeat while bytes move.
        let now = self.smol_now();
        let mut rounds = 0;
        loop {
            self.iface.poll(now, &mut self.phy, &mut self.sockets);
            rounds += 1;
            if !self.pump(cx) {
                break;
            }
            if rounds == 4 {
                more = true;
                break;
            }
        }
        self.reap();

        // Stack → interface.
        while let Some(packet) = self.phy.tx.front() {
            let t = self.profiling.then(std::time::Instant::now);
            let sent = self.device.poll_send(cx, packet);
            if let Some(t) = t {
                io_time += t.elapsed();
            }
            match sent {
                Poll::Pending => break,
                Poll::Ready(result) => {
                    let len = packet.len() as u64;
                    self.phy.tx.pop_front();
                    match result {
                        Ok(()) => {
                            self.count(|c| &c.packets_out, 1);
                            self.count(|c| &c.bytes_out, len);
                        }
                        Err(e) => {
                            self.count(|c| &c.dropped, 1);
                            log::debug!("TUN write failed: {e}");
                        }
                    }
                }
            }
        }

        let now = Instant::now();
        if now >= self.next_sweep {
            self.sweep(now);
            self.next_sweep = now + SWEEP;
        }
        if let Some(started) = started {
            self.record(started.elapsed().saturating_sub(io_time), io_time, packets);
            if now >= self.next_report {
                log::info!("TUN stack: {}", self.diag.metrics());
            }
        }
        if now >= self.next_report {
            self.next_report = now + REPORT;
        }

        if more {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut deadline = self.next_sweep;
        if self.profiling {
            deadline = deadline.min(self.next_report);
        }
        if let Some(delay) = self.iface.poll_delay(self.smol_now(), &self.sockets) {
            deadline = deadline.min(now + Duration::from_micros(delay.total_micros()));
        }
        self.timer.as_mut().reset(deadline);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn record(&self, stack: Duration, io: Duration, packets: u64) {
        let c = &self.diag.counters;
        Counters::add(&c.stack_ns, stack.as_nanos() as u64);
        Counters::add(&c.io_ns, io.as_nanos() as u64);
        c.record_packets(stack, packets);
        let depth = self.phy.tx.len() as u64;
        Counters::set(&c.queue_depth, depth);
        c.queue_peak
            .fetch_max(depth, std::sync::atomic::Ordering::Relaxed);
        Counters::set(&c.tcp_connections, self.tcp.len() as u64);
        Counters::set(&c.udp_flows, self.udp.len() as u64);
    }

    fn inbound(&mut self, packet: &[u8]) {
        match packet::parse(packet) {
            Err(reject) => {
                self.count(|c| &c.dropped, 1);
                if self.diag.verbose() {
                    log::debug!("TUN packet dropped: {reject:?}");
                }
            }
            Ok(Inbound::Tcp { src, dst, syn, ip }) => {
                if syn && !self.tuples.contains_key(&(src, dst)) {
                    self.accept(src, dst);
                }
                self.phy.rx.push_back(ip.to_vec());
            }
            Ok(Inbound::Udp { src, dst, payload }) => self.udp_out(src, dst, payload),
        }
    }

    /// A SYN to a new destination: a socket listening exactly there, and a request for the
    /// handler of its path. Over the limit, no socket: `smoltcp` answers the SYN with RST.
    fn accept(&mut self, src: SocketAddr, dst: SocketAddr) {
        if self.tcp.len() >= self.config.max_tcp {
            self.count(|c| &c.dropped, 1);
            if self.diag.verbose() {
                log::debug!("TUN TCP {src} -> {dst}: connection limit");
            }
            return;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; self.config.tcp_buffer]),
            tcp::SocketBuffer::new(vec![0u8; self.config.tcp_buffer]),
        );
        socket.set_nagle_enabled(false);
        socket.set_timeout(Some(TCP_TIMEOUT));
        if socket.listen(dst).is_err() {
            return;
        }
        let handle = self.sockets.add(socket);
        let path = self.rules.path(dst);
        let (io, remote) = tokio::io::duplex(DUPLEX_BUFFER);
        self.tcp.insert(
            handle,
            Conn {
                io,
                src,
                dst,
                path,
                established: false,
                io_shut: false,
                io_eof: false,
            },
        );
        self.tuples.insert((src, dst), handle);
        if self.diag.verbose() {
            log::debug!("TUN TCP {src} -> {dst}: open, {path:?}");
        }
        let request = TcpRequest {
            dst: target(dst),
            io: Box::new(remote),
        };
        match path {
            Path::Tunnel => self.tunnel.tcp(request),
            Path::Direct => self.direct.tcp(request),
        }
    }

    fn pump(&mut self, cx: &mut Context<'_>) -> bool {
        let mut progress = false;
        for (&handle, conn) in &mut self.tcp {
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            progress |= conn.pump(socket, cx, &self.split);
        }
        progress
    }

    /// Drops connections that are over, and listeners whose SYN `smoltcp` did not take.
    fn reap(&mut self) {
        let done: Vec<SocketHandle> = self
            .tcp
            .keys()
            .copied()
            .filter(|&handle| {
                matches!(
                    self.sockets.get::<tcp::Socket>(handle).state(),
                    tcp::State::Closed | tcp::State::TimeWait | tcp::State::Listen
                )
            })
            .collect();
        for handle in done {
            self.sockets.remove(handle);
            if let Some(conn) = self.tcp.remove(&handle) {
                self.tuples.remove(&(conn.src, conn.dst));
                if self.diag.verbose() {
                    log::debug!("TUN TCP {} -> {}: closed", conn.src, conn.dst);
                }
            }
        }
    }

    fn udp_out(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        let now = Instant::now();
        let path = self.rules.path(dst);
        let key = (src, path);
        let mut packet = UdpPacket {
            src,
            dst,
            payload: Bytes::copy_from_slice(payload),
        };
        if let Some(flow) = self.udp.get_mut(&key) {
            flow.last = now;
            match flow.tx.try_send(packet) {
                Ok(()) => {
                    self.split.sent(path, payload.len());
                    return;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.count(|c| &c.dropped, 1);
                    return;
                }
                // The handler ended the flow: open a new one.
                Err(mpsc::error::TrySendError::Closed(p)) => {
                    self.udp.remove(&key);
                    packet = p;
                }
            }
        }
        if self.udp.len() >= self.config.max_udp {
            self.count(|c| &c.dropped, 1);
            if self.diag.verbose() {
                log::debug!("TUN UDP {src} -> {dst}: flow limit");
            }
            return;
        }
        if self.diag.verbose() {
            log::debug!("TUN UDP {src}: new {path:?} flow, first to {dst}");
        }
        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        let _ = tx.try_send(packet);
        self.split.sent(path, payload.len());
        match path {
            Path::Tunnel => self.tunnel.udp(src, rx, self.tunnel_replies.tx.clone()),
            Path::Direct => self.direct.udp(src, rx, self.direct_replies.tx.clone()),
        }
        self.udp.insert(key, Flow { tx, last: now });
    }

    fn reply(&mut self, path: Path, reply: UdpPacket) {
        if let Some(flow) = self.udp.get_mut(&(reply.dst, path)) {
            flow.last = Instant::now();
        }
        match packet::udp(reply.src, reply.dst, &reply.payload, self.config.mtu) {
            Some(packet) if self.phy.tx.len() < OUT_QUEUE => {
                self.split.received(path, reply.payload.len());
                self.phy.tx.push_back(packet);
            }
            _ => self.count(|c| &c.dropped, 1),
        }
    }

    /// Closes flows idle for `udp_idle` or ended by the handler.
    fn sweep(&mut self, now: Instant) {
        let idle = self.config.udp_idle;
        let verbose = self.diag.verbose();
        self.udp.retain(|(src, path), flow| {
            let keep = now.duration_since(flow.last) < idle && !flow.tx.is_closed();
            if !keep && verbose {
                log::debug!("TUN UDP {src}: {path:?} flow closed");
            }
            keep
        });
    }
}

#[cfg(test)]
mod tests;

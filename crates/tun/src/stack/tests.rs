//! The stack over a datagram socketpair: the far end plays the phone's apps with a second
//! `smoltcp` interface, both handlers echo everything back and report what reached them.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram as StdDatagram;
use std::sync::atomic::Ordering;

use proto::{Host, TargetAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixDatagram;
use tokio::task::JoinHandle;

use super::*;
use crate::{FdDevice, IpNet, SplitConfig, SplitMode, SplitStats, StackMetrics};

/// Echoes TCP and UDP, reporting every TCP destination and UDP flow with its path.
struct Echo {
    path: Path,
    opened: mpsc::UnboundedSender<(Path, TargetAddr)>,
    flows: mpsc::UnboundedSender<(Path, SocketAddr)>,
}

impl Handler for Echo {
    fn tcp(&self, request: TcpRequest) {
        let _ = self.opened.send((self.path, request.dst.clone()));
        tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(request.io);
            let _ = tokio::io::copy(&mut read, &mut write).await;
            let _ = write.shutdown().await;
        });
    }

    fn udp(
        &self,
        source: SocketAddr,
        mut datagrams: mpsc::Receiver<UdpPacket>,
        replies: mpsc::Sender<UdpPacket>,
    ) {
        let _ = self.flows.send((self.path, source));
        tokio::spawn(async move {
            while let Some(p) = datagrams.recv().await {
                let reply = UdpPacket {
                    src: p.dst,
                    dst: p.src,
                    payload: p.payload,
                };
                let _ = replies.send(reply).await;
            }
        });
    }
}

struct Harness {
    link: UnixDatagram,
    diag: Arc<Diagnostics>,
    split: Arc<Split>,
    opened: mpsc::UnboundedReceiver<(Path, TargetAddr)>,
    flows: mpsc::UnboundedReceiver<(Path, SocketAddr)>,
    stack: JoinHandle<io::Result<()>>,
}

fn start(config: Config, profiling: bool) -> Harness {
    start_split(config, profiling, SplitConfig::default())
}

fn start_split(config: Config, profiling: bool, split: SplitConfig) -> Harness {
    let (ours, theirs) = StdDatagram::pair().unwrap();
    ours.set_nonblocking(true).unwrap();
    theirs.set_nonblocking(true).unwrap();
    let device = FdDevice::new(OwnedFd::from(ours)).unwrap();
    let diag = Arc::new(Diagnostics::default());
    diag.set(profiling, false);
    let split = Arc::new(Split::new(&split));
    let (opened_tx, opened) = mpsc::unbounded_channel();
    let (flows_tx, flows) = mpsc::unbounded_channel();
    let echo = |path| Echo {
        path,
        opened: opened_tx.clone(),
        flows: flows_tx.clone(),
    };
    let stack = tokio::spawn(run(
        device,
        echo(Path::Tunnel),
        echo(Path::Direct),
        split.clone(),
        config,
        diag.clone(),
    ));
    Harness {
        link: UnixDatagram::from_std(theirs).unwrap(),
        diag,
        split,
        opened,
        flows,
        stack,
    }
}

/// The apps' side: an ordinary `smoltcp` interface at 10.0.0.2 / fd00::2.
struct Apps {
    iface: Interface,
    sockets: SocketSet<'static>,
    phy: Phy,
    epoch: Instant,
    /// Size of every packet the stack wrote.
    seen: Vec<usize>,
}

const APP_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const APP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

impl Apps {
    fn new() -> Self {
        let mut phy = Phy {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: 1500,
        };
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut phy,
            SmolInstant::ZERO,
        );
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(APP_V4.into(), 24)).unwrap();
            addrs.push(IpCidr::new(APP_V6.into(), 64)).unwrap();
        });
        let routes = iface.routes_mut();
        routes
            .add_default_ipv4_route(Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        routes
            .add_default_ipv6_route(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
            .unwrap();
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            phy,
            epoch: Instant::now(),
            seen: Vec::new(),
        }
    }

    fn connect(&mut self, remote: SocketAddr, local_port: u16) -> SocketHandle {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        );
        socket
            .connect(self.iface.context(), remote, local_port)
            .unwrap();
        self.sockets.add(socket)
    }

    fn socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(handle)
    }

    /// Lets the interface run, sends what it emitted, takes what the stack wrote.
    async fn step(&mut self, link: &UnixDatagram) {
        let now = SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64);
        self.iface.poll(now, &mut self.phy, &mut self.sockets);
        while let Some(packet) = self.phy.tx.pop_front() {
            link.send(&packet).await.unwrap();
        }
        let mut buf = vec![0u8; MAX_PACKET];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(2), link.recv(&mut buf)).await
        {
            self.take(&buf[..n]);
            while let Ok(n) = link.try_recv(&mut buf) {
                self.take(&buf[..n]);
            }
        }
    }

    fn take(&mut self, packet: &[u8]) {
        self.seen.push(packet.len());
        self.phy.rx.push_back(packet.to_vec());
    }

    async fn until(&mut self, link: &UnixDatagram, mut done: impl FnMut(&mut Self) -> bool) {
        for _ in 0..5000 {
            if done(self) {
                return;
            }
            self.step(link).await;
        }
        panic!("condition not reached");
    }

    /// Sends `data` on `handle` and returns what comes back, until `data.len()` bytes did.
    async fn echo(&mut self, link: &UnixDatagram, handle: SocketHandle, data: &[u8]) -> Vec<u8> {
        self.until(link, |a| a.socket(handle).may_send()).await;
        let mut sent = 0;
        let mut got = Vec::new();
        self.until(link, |a| {
            let socket = a.socket(handle);
            if sent < data.len() && socket.can_send() {
                sent += socket.send_slice(&data[sent..]).unwrap();
            }
            while socket.can_recv() {
                let mut buf = [0u8; 4096];
                let n = socket.recv_slice(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
            }
            got.len() >= data.len()
        })
        .await;
        got
    }
}

async fn udp_exchange(link: &UnixDatagram, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
    link.send(&packet::udp(src, dst, payload, MAX_PACKET).unwrap())
        .await
        .unwrap();
    let mut buf = vec![0u8; MAX_PACKET];
    let n = tokio::time::timeout(Duration::from_secs(5), link.recv(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    assert_eq!(
        packet::parse(&buf[..n]),
        Ok(Inbound::Udp {
            src: dst,
            dst: src,
            payload
        })
    );
}

fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::from(ip).into(), port)
}

fn ip(addr: &str) -> SocketAddr {
    addr.parse().unwrap()
}

#[tokio::test]
async fn a01_t1_ipv4_tcp_reaches_handler_with_its_destination_and_echoes() {
    let mut h = start(Config::default(), true);
    let mut apps = Apps::new();
    let conn = apps.connect(v4([93, 184, 216, 34], 80), 40000);
    assert_eq!(apps.echo(&h.link, conn, b"ping").await, b"ping");
    assert_eq!(
        h.opened.try_recv().unwrap(),
        (
            Path::Tunnel,
            TargetAddr {
                host: Host::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: 80
            }
        )
    );
    assert!(h.opened.try_recv().is_err(), "one connection, one request");

    // Close from the app: the FIN reaches the handler, which closes back; the stack forgets it.
    apps.socket(conn).close();
    apps.until(&h.link, |a| {
        matches!(
            a.socket(conn).state(),
            tcp::State::Closed | tcp::State::TimeWait
        )
    })
    .await;
    apps.until(&h.link, |_| {
        h.diag.counters.tcp_connections.load(Ordering::Relaxed) == 0
    })
    .await;
    assert!(!h.stack.is_finished());
}

#[tokio::test]
async fn a01_t2_ipv6_tcp_is_carried() {
    let mut h = start(Config::default(), false);
    let mut apps = Apps::new();
    let conn = apps.connect(ip("[2001:db8::1]:443"), 40001);
    let data: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
    assert_eq!(apps.echo(&h.link, conn, &data).await, data);
    assert_eq!(
        h.opened.try_recv().unwrap(),
        (
            Path::Tunnel,
            TargetAddr {
                host: Host::V6("2001:db8::1".parse().unwrap()),
                port: 443
            }
        )
    );
}

#[tokio::test]
async fn parallel_connections_to_one_destination_stay_apart() {
    let h = start(Config::default(), false);
    let mut apps = Apps::new();
    let dst = v4([1, 1, 1, 1], 443);
    let a = apps.connect(dst, 41000);
    let b = apps.connect(dst, 41001);
    assert_eq!(apps.echo(&h.link, a, b"first").await, b"first");
    assert_eq!(apps.echo(&h.link, b, b"second").await, b"second");
}

#[tokio::test]
async fn a01_t3_udp_datagram_goes_out_and_reply_comes_back() {
    let h = start(Config::default(), false);
    let app = SocketAddr::new(APP_V4.into(), 5353);
    udp_exchange(&h.link, app, v4([8, 8, 8, 8], 53), b"query").await;
    // Same flow, another destination.
    udp_exchange(&h.link, app, v4([1, 1, 1, 1], 53), b"again").await;
    let app6 = SocketAddr::new(APP_V6.into(), 3478);
    udp_exchange(&h.link, app6, ip("[2001:db8::3]:3478"), b"stun").await;
}

#[tokio::test]
async fn a01_t4_broken_packets_are_dropped_and_the_stack_goes_on() {
    let h = start(Config::default(), true);
    let good = packet::udp(v4([10, 0, 0, 2], 5000), v4([8, 8, 8, 8], 53), b"x", 1400).unwrap();
    let junk: Vec<Vec<u8>> = vec![
        vec![0x45],
        good[..10].to_vec(),
        good[..good.len() - 1].to_vec(),
        vec![0x60; 39],
        vec![0xff; 100],
        {
            let mut fragment = good.clone();
            fragment[6] |= 0x20;
            fragment
        },
    ];
    for packet in &junk {
        h.link.send(packet).await.unwrap();
    }
    udp_exchange(
        &h.link,
        v4([10, 0, 0, 2], 5000),
        v4([8, 8, 8, 8], 53),
        b"alive",
    )
    .await;
    assert!(!h.stack.is_finished());
    assert_eq!(h.diag.metrics().dropped, junk.len() as u64);
}

#[tokio::test]
async fn a01_t5_nothing_written_to_the_interface_exceeds_the_mtu() {
    let mtu = 600;
    let h = start(
        Config {
            mtu,
            ..Config::default()
        },
        false,
    );
    let mut apps = Apps::new();
    let conn = apps.connect(v4([93, 184, 216, 34], 80), 40002);
    let data = vec![7u8; 100_000];
    assert_eq!(apps.echo(&h.link, conn, &data).await, data);
    assert!(apps.seen.len() > 100_000 / mtu, "data came back segmented");
    assert!(apps.seen.iter().all(|&n| n <= mtu), "{:?}", apps.seen);

    // A UDP reply that fits exactly passes; one byte more is dropped, not fragmented.
    let (app, dst) = (v4([10, 0, 0, 2], 6000), v4([9, 9, 9, 9], 9));
    udp_exchange(&h.link, app, dst, &vec![1u8; mtu - 28]).await;
    let big = packet::udp(app, dst, &vec![1u8; mtu - 27], MAX_PACKET).unwrap();
    h.link.send(&big).await.unwrap();
    udp_exchange(&h.link, app, dst, b"small").await;
}

#[tokio::test]
async fn a01_t6_counters_only_move_while_profiling() {
    let h = start(Config::default(), false);
    let mut apps = Apps::new();
    let conn = apps.connect(v4([93, 184, 216, 34], 80), 40003);
    apps.echo(&h.link, conn, b"quiet").await;
    udp_exchange(&h.link, v4([10, 0, 0, 2], 7000), v4([8, 8, 8, 8], 53), b"q").await;
    let c = &h.diag.counters;
    for counter in [
        &c.packets_in,
        &c.packets_out,
        &c.bytes_in,
        &c.stack_ns,
        &c.io_ns,
        &c.tcp_connections,
        &c.udp_flows,
    ] {
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
    assert_eq!(h.diag.metrics(), StackMetrics::default());

    // Switched on while running.
    h.diag.set(true, true);
    apps.echo(&h.link, conn, b"loud").await;
    udp_exchange(&h.link, v4([10, 0, 0, 2], 7000), v4([8, 8, 8, 8], 53), b"q").await;
    let m = h.diag.metrics();
    // At least the TCP data and the UDP datagram, each way.
    assert!(m.packets_in >= 2 && m.packets_out >= 2, "{m:?}");
    assert!(m.bytes_in > 0 && m.bytes_out > 0, "{m:?}");
    assert_eq!((m.tcp_connections, m.udp_flows), (1, 1), "{m:?}");
    assert!(
        m.stack_time > Duration::ZERO && m.io_time > Duration::ZERO,
        "{m:?}"
    );
    assert!(m.packet_time_p50 > Duration::ZERO, "{m:?}");
    assert!(m.packet_time_p99 >= m.packet_time_p50, "{m:?}");
    assert!(m.packets_per_sec() > 0.0);
}

#[tokio::test]
async fn idle_udp_flows_are_closed() {
    let h = start(
        Config {
            udp_idle: Duration::from_millis(100),
            ..Config::default()
        },
        true,
    );
    udp_exchange(&h.link, v4([10, 0, 0, 2], 8000), v4([8, 8, 8, 8], 53), b"q").await;
    assert_eq!(h.diag.metrics().udp_flows, 1);
    // The sweep runs every `SWEEP`.
    tokio::time::sleep(SWEEP + Duration::from_millis(500)).await;
    udp_exchange(&h.link, v4([10, 0, 0, 2], 8001), v4([8, 8, 8, 8], 53), b"q").await;
    assert_eq!(h.diag.metrics().udp_flows, 1, "the first flow was swept");
}

#[tokio::test]
async fn connections_over_the_limit_are_refused() {
    let h = start(
        Config {
            max_tcp: 1,
            ..Config::default()
        },
        false,
    );
    let mut apps = Apps::new();
    let a = apps.connect(v4([1, 1, 1, 1], 443), 42000);
    assert_eq!(apps.echo(&h.link, a, b"one").await, b"one");
    let b = apps.connect(v4([1, 1, 1, 1], 443), 42001);
    apps.until(&h.link, |apps| apps.socket(b).state() == tcp::State::Closed)
        .await;
}

fn nets(list: &[&str]) -> Vec<IpNet> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

fn tcp_dst(addr: SocketAddr) -> TargetAddr {
    crate::engine::target(addr)
}

#[tokio::test]
async fn a02_include_sends_listed_traffic_to_the_tunnel_and_the_rest_direct() {
    let mut h = start_split(
        Config::default(),
        false,
        SplitConfig {
            mode: SplitMode::Include,
            routes: nets(&["93.184.216.0/24", "2606:4700::/32"]),
        },
    );
    let mut apps = Apps::new();
    for (port, (dst, path)) in (43000..).zip([
        (v4([93, 184, 216, 34], 443), Path::Tunnel),
        (v4([1, 1, 1, 1], 443), Path::Direct),
        (ip("[2606:4700::1111]:443"), Path::Tunnel),
        (ip("[2001:db8::1]:443"), Path::Direct),
    ]) {
        let conn = apps.connect(dst, port);
        assert_eq!(apps.echo(&h.link, conn, b"x").await, b"x");
        assert_eq!(h.opened.try_recv().unwrap(), (path, tcp_dst(dst)), "{dst}");
    }

    // UDP: one source, two destinations on different paths, two flows.
    let app = v4([10, 0, 0, 2], 5000);
    udp_exchange(&h.link, app, v4([93, 184, 216, 1], 3478), b"in").await;
    udp_exchange(&h.link, app, v4([8, 8, 4, 4], 3478), b"out").await;
    assert_eq!(h.flows.try_recv().unwrap(), (Path::Tunnel, app));
    assert_eq!(h.flows.try_recv().unwrap(), (Path::Direct, app));
    // DNS goes through the tunnel even though the resolver is not listed.
    udp_exchange(
        &h.link,
        v4([10, 0, 0, 2], 5001),
        v4([192, 168, 1, 1], 53),
        b"q",
    )
    .await;
    assert_eq!(
        h.flows.try_recv().unwrap(),
        (Path::Tunnel, v4([10, 0, 0, 2], 5001))
    );
}

#[tokio::test]
async fn a02_exclude_sends_listed_traffic_direct() {
    let mut h = start_split(
        Config::default(),
        false,
        SplitConfig {
            mode: SplitMode::Exclude,
            routes: nets(&["192.168.0.0/16"]),
        },
    );
    let mut apps = Apps::new();
    let lan = apps.connect(v4([192, 168, 1, 10], 80), 44000);
    apps.echo(&h.link, lan, b"x").await;
    let wan = apps.connect(v4([1, 1, 1, 1], 80), 44001);
    apps.echo(&h.link, wan, b"x").await;
    assert_eq!(h.opened.try_recv().unwrap().0, Path::Direct);
    assert_eq!(h.opened.try_recv().unwrap().0, Path::Tunnel);
}

#[tokio::test]
async fn a02_rules_change_without_restarting_and_open_connections_keep_their_path() {
    let mut h = start(Config::default(), false);
    let mut apps = Apps::new();
    let dst = v4([1, 1, 1, 1], 443);
    let before = apps.connect(dst, 45000);
    apps.echo(&h.link, before, b"a").await;
    assert_eq!(h.opened.try_recv().unwrap().0, Path::Tunnel);

    h.split.set(&SplitConfig {
        mode: SplitMode::Include,
        routes: Vec::new(),
    });
    let after = apps.connect(dst, 45001);
    apps.echo(&h.link, after, b"b").await;
    assert_eq!(h.opened.try_recv().unwrap().0, Path::Direct);
    // The first connection still works, still through the tunnel.
    assert_eq!(apps.echo(&h.link, before, b"c").await, b"c");
    assert!(h.opened.try_recv().is_err());
    assert!(!h.stack.is_finished());
}

#[tokio::test]
async fn a02_traffic_is_counted_per_path() {
    let h = start_split(
        Config::default(),
        false,
        SplitConfig {
            mode: SplitMode::Include,
            routes: nets(&["93.184.216.34"]),
        },
    );
    let mut apps = Apps::new();
    let tunneled = apps.connect(v4([93, 184, 216, 34], 443), 46000);
    apps.echo(&h.link, tunneled, &[1u8; 3000]).await;
    let direct = apps.connect(v4([1, 1, 1, 1], 443), 46001);
    apps.echo(&h.link, direct, &[2u8; 500]).await;
    udp_exchange(
        &h.link,
        v4([10, 0, 0, 2], 6000),
        v4([1, 1, 1, 1], 443),
        &[3u8; 40],
    )
    .await;
    assert_eq!(
        h.split.stats(),
        SplitStats {
            tunnel_sent: 3000,
            tunnel_received: 3000,
            direct_sent: 540,
            direct_received: 540,
        }
    );
}

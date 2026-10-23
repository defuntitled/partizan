//! Lengths read from the network are checked before anything is allocated for them.
//!
//! A counting allocator records the largest single allocation while hostile inputs are
//! decoded. Separate test binary, so the allocator affects nothing else.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use proto::auth::{
    AuthRequest, ClientHandshake, ClientInfo, ConnectionUri, DeviceId, Token, Transport,
    TransportMode,
};
use proto::mux::{Mux, Role};
use proto::{Connect, ControlFrame, UdpDatagram, varint};

struct Counting;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        // SAFETY: forwarding the caller's layout to the system allocator unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Tests share the counter, so run them one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// Largest allocation made while running `f`.
fn largest_allocation(f: impl FnOnce()) -> usize {
    LARGEST.store(0, Ordering::Relaxed);
    f();
    LARGEST.load(Ordering::Relaxed)
}

fn varint_bytes(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint::encode(value, &mut out).unwrap();
    out
}

/// A frame header claiming a huge length, followed by a little data.
fn huge(prefix: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    out.extend(varint_bytes(varint::MAX));
    out.extend_from_slice(&[0; 64]);
    out
}

const BUDGET: usize = 4 * 1024;

#[test]
fn c06_t3_declared_lengths_over_the_limit_allocate_nothing_big() {
    let _serial = SERIAL.lock().unwrap();
    // Connect: padding_len = 2^62 − 1.
    let mut connect = vec![0x01, 0x01, 1, 2, 3, 4, 0, 80];
    connect = huge(&connect);
    // Control frame: length = 2^62 − 1.
    let control = huge(&[0x10]);
    // Mux DATA frame: length = 2^62 − 1 on stream 1.
    let mux = huge(&[0x01, 0x00]);
    // HTTP/3 HEADERS frame: length = 2^62 − 1.
    let h3 = huge(&[0x01]);
    // HTTP/1.1 head with no end.
    let http1 = vec![b'a'; 64 * 1024];
    // QPACK string literal claiming 2^62 bytes inside a small HEADERS frame.
    let mut qpack = vec![0x00, 0x00, 0x5f, 0x7f];
    qpack.extend_from_slice(&[0xff; 8]);
    qpack.push(0x01);
    let mut h3_qpack = vec![0x01, qpack.len() as u8];
    h3_qpack.extend(qpack);

    let largest = largest_allocation(|| {
        assert!(Connect::decode(&connect).is_err());
        assert!(ControlFrame::decode(&control).is_err());
        assert!(Mux::new(Role::Server).handle_input(&mux).is_err());
        assert!(AuthRequest::decode(Transport::Quic, &h3).is_err());
        assert!(AuthRequest::decode(Transport::Quic, &h3_qpack).is_err());
        assert!(AuthRequest::decode(Transport::Tls, &http1).is_err());
        assert!(UdpDatagram::decode(Bytes::from_static(&[0xff; 9])).is_err());
    });
    assert!(largest <= BUDGET, "largest allocation {largest} bytes");
}

#[test]
fn c06_t3_client_handshake_does_not_buffer_without_bound() {
    let _serial = SERIAL.lock().unwrap();
    let uri = ConnectionUri {
        device_id: DeviceId([1; 16]),
        token: Token::from_bytes([2; 32]),
        host: "cdn.example.com".into(),
        port: 443,
        sni: None,
        path: "/api/v2/sync".into(),
        pin: None,
        transport: TransportMode::Auto,
        insecure: false,
        passthrough: None,
    };
    let info = ClientInfo::new("openwrt", "0.1.0");
    for transport in [Transport::Quic, Transport::Tls] {
        let (mut client, _) =
            ClientHandshake::start(transport, &uri, &info, Instant::now()).unwrap();
        // A server that streams garbage without ever completing a response.
        let chunk = [0x21u8; 1024];
        let mut failed = false;
        for _ in 0..64 {
            if client.handle_input(&chunk).is_err() {
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "{transport:?}: handshake kept buffering 64 KiB of garbage"
        );
    }
}

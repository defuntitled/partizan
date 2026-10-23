//! Property tests: every frame type survives encode → decode, and decoders never panic.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use proptest::prelude::*;
use proto::mux::{Event, Mux, Read, Role};
use proto::{
    Connect, ConnectResult, ConnectStatus, ControlFrame, ErrorCode, Host, TargetAddr, UdpDatagram,
    varint,
};

fn addr() -> impl Strategy<Value = TargetAddr> {
    let host = prop_oneof![
        any::<[u8; 4]>().prop_map(|b| Host::V4(Ipv4Addr::from(b))),
        any::<[u8; 16]>().prop_map(|b| Host::V6(Ipv6Addr::from(b))),
        "[a-z0-9.-]{1,255}".prop_map(Host::Domain),
        // Multi-byte UTF-8 up to the 255-byte limit.
        "[а-я]{1,127}".prop_map(Host::Domain),
    ];
    (host, any::<u16>()).prop_map(|(host, port)| TargetAddr { host, port })
}

fn control() -> impl Strategy<Value = ControlFrame> {
    let id = 0..=varint::MAX;
    prop_oneof![
        any::<u64>().prop_map(|nonce| ControlFrame::Ping { nonce }),
        any::<u64>().prop_map(|nonce| ControlFrame::Pong { nonce }),
        (id.clone(), any::<u8>())
            .prop_map(|(session_id, reason)| ControlFrame::UdpClose { session_id, reason }),
        (id.clone(), id).prop_map(|(code, retry_after_ms)| ControlFrame::GoAway {
            code: ErrorCode(code),
            retry_after_ms
        }),
        (0..=proto::control::MAX_CONTROL_BODY).prop_map(|len| ControlFrame::Padding { len }),
    ]
}

proptest! {
    #[test]
    fn c06_t2_varint_roundtrips(value in 0..=varint::MAX) {
        let mut out = Vec::new();
        varint::encode(value, &mut out).unwrap();
        prop_assert_eq!(varint::decode(&out), Ok((value, out.len())));
    }

    #[test]
    fn c06_t2_connect_roundtrips(addr in addr(), padding in 0..=proto::connect::MAX_PADDING) {
        let c = Connect { addr, padding };
        let mut out = Vec::new();
        c.encode(&mut out).unwrap();
        prop_assert_eq!(Connect::decode(&out), Ok((c, out.len())));
    }

    #[test]
    fn c06_t2_connect_result_roundtrips(code in 0u8..=8, padding in 0..=proto::connect::MAX_PADDING) {
        let r = ConnectResult { status: ConnectStatus::try_from(code).unwrap(), padding };
        let mut out = Vec::new();
        r.encode(&mut out).unwrap();
        prop_assert_eq!(ConnectResult::decode(&out), Ok((r, out.len())));
    }

    #[test]
    fn c06_t2_udp_datagram_roundtrips(
        session_id in 0..=varint::MAX,
        addr in proptest::option::of(addr()),
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let d = UdpDatagram { session_id, addr, payload: Bytes::from(payload) };
        let mut out = Vec::new();
        d.encode(&mut out).unwrap();
        prop_assert_eq!(UdpDatagram::decode(Bytes::from(out)), Ok(d));
    }

    #[test]
    fn c06_t2_control_frames_roundtrip(frames in proptest::collection::vec(control(), 1..8)) {
        let mut out = Vec::new();
        for f in &frames {
            f.encode(&mut out).unwrap();
        }
        let mut rest = &out[..];
        for f in frames {
            let (decoded, used) = ControlFrame::decode(rest).unwrap();
            prop_assert_eq!(decoded, Some(f));
            rest = &rest[used..];
        }
        prop_assert!(rest.is_empty());
    }

    #[test]
    fn decoders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = varint::decode(&data);
        let _ = Connect::decode(&data);
        let _ = ConnectResult::decode(&data);
        let _ = ControlFrame::decode(&data);
        let _ = UdpDatagram::decode(Bytes::from(data.clone()));
        let _ = Mux::new(Role::Server).handle_input(&data);
        let _ = Mux::new(Role::Client).handle_input(&data);
    }
}

/// One step of mux traffic from the client side.
#[derive(Debug, Clone)]
enum Op {
    Open,
    Write(usize, Vec<u8>),
    Finish(usize),
    Datagram(Vec<u8>),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        Just(Op::Open),
        (
            any::<usize>(),
            proptest::collection::vec(any::<u8>(), 1..40_000)
        )
            .prop_map(|(i, d)| Op::Write(i, d)),
        any::<usize>().prop_map(Op::Finish),
        proptest::collection::vec(any::<u8>(), 0..1500).prop_map(Op::Datagram),
    ]
}

fn pump(a: &mut Mux, b: &mut Mux) {
    loop {
        let (mut ab, mut ba) = (Vec::new(), Vec::new());
        while a.poll_transmit(&mut ab) {}
        while b.poll_transmit(&mut ba) {}
        if ab.is_empty() && ba.is_empty() {
            break;
        }
        b.handle_input(&ab).unwrap();
        a.handle_input(&ba).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Mux frames of every type in random interleavings: stream bytes and datagrams arrive
    /// intact and in order.
    #[test]
    fn c06_t2_mux_traffic_roundtrips(ops in proptest::collection::vec(op(), 1..40)) {
        let (mut c, mut s) = (Mux::new(Role::Client), Mux::new(Role::Server));
        let mut streams: Vec<(u64, Vec<u8>, bool)> = Vec::new();
        let mut sent_datagrams = Vec::new();
        let mut received: std::collections::HashMap<u64, (Vec<u8>, bool)> = Default::default();
        let mut got_datagrams = Vec::new();
        for op in ops {
            match op {
                Op::Open => streams.push((c.open_stream().unwrap(), Vec::new(), false)),
                Op::Write(i, data) if !streams.is_empty() => {
                    let n = streams.len();
                    let (id, sent, fin) = &mut streams[i % n];
                    if !*fin {
                        let n = c.write(*id, &data).unwrap();
                        sent.extend_from_slice(&data[..n]);
                    }
                }
                Op::Finish(i) if !streams.is_empty() => {
                    let n = streams.len();
                    let (id, _, fin) = &mut streams[i % n];
                    if !*fin {
                        c.finish(*id).unwrap();
                        *fin = true;
                    }
                }
                Op::Datagram(d) => {
                    c.send_datagram(Bytes::from(d.clone())).unwrap();
                    sent_datagrams.push(d);
                }
                _ => {}
            }
            pump(&mut c, &mut s);
            while let Some(event) = s.poll_event() {
                match event {
                    Event::Datagram(d) => got_datagrams.push(d.to_vec()),
                    Event::Readable(id) => loop {
                        let entry = received.entry(id).or_default();
                        match s.read(id, usize::MAX).unwrap() {
                            Read::Data(chunk) => entry.0.extend_from_slice(&chunk),
                            Read::Finished => { entry.1 = true; break; }
                            Read::Blocked => break,
                        }
                    },
                    _ => {}
                }
            }
            // Reading released window; let WINDOW_UPDATEs through.
            pump(&mut c, &mut s);
        }
        prop_assert_eq!(got_datagrams, sent_datagrams);
        for (id, sent, fin) in streams {
            let (got, got_fin) = received.remove(&id).unwrap_or_default();
            prop_assert_eq!(got, sent);
            prop_assert_eq!(got_fin, fin);
        }
    }
}

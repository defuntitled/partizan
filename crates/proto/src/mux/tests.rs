use super::*;

fn pair() -> (Mux, Mux) {
    (Mux::new(Role::Client), Mux::new(Role::Server))
}

fn transmit(m: &mut Mux) -> Vec<u8> {
    let mut out = Vec::new();
    while m.poll_transmit(&mut out) {}
    out
}

/// Moves bytes both ways until neither side has anything to send.
fn pump(a: &mut Mux, b: &mut Mux) {
    loop {
        let ab = transmit(a);
        let ba = transmit(b);
        if ab.is_empty() && ba.is_empty() {
            break;
        }
        b.handle_input(&ab).unwrap();
        a.handle_input(&ba).unwrap();
    }
}

fn events(m: &mut Mux) -> Vec<Event> {
    std::iter::from_fn(|| m.poll_event()).collect()
}

/// Reads everything buffered; `true` if the stream reached FIN.
fn read_all(m: &mut Mux, id: u64) -> (Vec<u8>, bool) {
    let mut data = Vec::new();
    loop {
        match m.read(id, usize::MAX).unwrap() {
            Read::Data(chunk) => data.extend_from_slice(&chunk),
            Read::Blocked => return (data, false),
            Read::Finished => return (data, true),
        }
    }
}

fn frames(mut bytes: &[u8]) -> Vec<(u64, FrameType, Vec<u8>)> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (h, n) = frame::decode(bytes).unwrap().unwrap();
        out.push((h.stream_id, h.ty, bytes[n..n + h.len].to_vec()));
        bytes = &bytes[n + h.len..];
    }
    out
}

fn kinds(bytes: &[u8]) -> Vec<(u64, FrameType)> {
    frames(bytes)
        .into_iter()
        .map(|(id, ty, _)| (id, ty))
        .collect()
}

fn raw(id: u64, ty: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    frame::encode(id, ty, payload, &mut out);
    out
}

fn is_protocol_error(r: Result<(), MuxError>) -> bool {
    matches!(r, Err(e) if e.code() == Some(ErrorCode::PROTOCOL_ERROR))
}

#[test]
fn c04_t1_open_exchange_and_close_with_fin() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    assert_eq!(c.write(id, b"connect+hello").unwrap(), 13);
    let wire = transmit(&mut c);
    assert_eq!(
        frames(&wire),
        [(id, FrameType::Open, b"connect+hello".to_vec())]
    );
    s.handle_input(&wire).unwrap();
    assert_eq!(
        events(&mut s),
        [Event::StreamOpened(id), Event::Readable(id)]
    );
    assert_eq!(read_all(&mut s, id), (b"connect+hello".to_vec(), false));

    s.write(id, b"response").unwrap();
    s.finish(id).unwrap();
    c.finish(id).unwrap();
    pump(&mut c, &mut s);
    assert_eq!(read_all(&mut c, id), (b"response".to_vec(), true));
    assert_eq!(read_all(&mut s, id), (vec![], true));
    assert_eq!((c.open_streams(), s.open_streams()), (0, 0));
}

#[test]
fn c04_t2_half_close_keeps_the_other_direction() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    c.write(id, b"request").unwrap();
    c.finish(id).unwrap();
    pump(&mut c, &mut s);
    assert_eq!(read_all(&mut s, id), (b"request".to_vec(), true));
    assert_eq!(c.write(id, b"x"), Err(MuxError::StreamFinished(id)));

    // The server's direction is still open after the client's FIN.
    s.write(id, b"late reply").unwrap();
    pump(&mut c, &mut s);
    assert_eq!(read_all(&mut c, id), (b"late reply".to_vec(), false));
    s.finish(id).unwrap();
    pump(&mut c, &mut s);
    assert_eq!(read_all(&mut c, id), (vec![], true));
    assert_eq!((c.open_streams(), s.open_streams()), (0, 0));

    // `finish` before any data still opens the stream, then sends FIN.
    let id = c.open_stream().unwrap();
    c.finish(id).unwrap();
    assert_eq!(
        kinds(&transmit(&mut c)),
        [(id, FrameType::Open), (id, FrameType::Fin)]
    );
}

#[test]
fn c04_t3_rst_closes_the_stream_with_a_code() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    c.write(id, b"x").unwrap();
    pump(&mut c, &mut s);
    events(&mut s);

    s.reset(id, ErrorCode::TARGET_REFUSED).unwrap();
    // Data already in flight when the RST crosses it is ignored, not an error.
    c.write(id, b"in flight").unwrap();
    pump(&mut c, &mut s);
    assert_eq!(
        events(&mut c),
        [Event::Reset {
            id,
            code: ErrorCode::TARGET_REFUSED
        }]
    );
    assert_eq!(c.write(id, b"y"), Err(MuxError::UnknownStream(id)));
    assert_eq!((c.open_streams(), s.open_streams()), (0, 0));

    // Resetting a stream the peer never saw sends nothing.
    let id = c.open_stream().unwrap();
    c.reset(id, ErrorCode::NO_ERROR).unwrap();
    assert!(transmit(&mut c).is_empty());
}

#[test]
fn c04_t4_data_beyond_window_waits_for_window_update() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    let data = vec![7u8; 300 * 1024];
    let taken = c.write(id, &data).unwrap();
    assert_eq!(taken as u64, INITIAL_WINDOW);

    let wire = transmit(&mut c);
    let sent = frames(&wire);
    assert!(sent.iter().all(|(_, _, p)| p.len() <= MAX_DATA));
    let total: usize = sent.iter().map(|(_, _, p)| p.len()).sum();
    assert_eq!(total as u64, INITIAL_WINDOW);
    s.handle_input(&wire).unwrap();

    assert_eq!(c.write(id, &data[taken..]).unwrap(), 0, "window is full");
    assert!(transmit(&mut c).is_empty());

    // Reading half the window releases exactly that much.
    let mut read = 0;
    while read < INITIAL_WINDOW as usize / 2 {
        match s.read(id, MAX_DATA).unwrap() {
            Read::Data(chunk) => read += chunk.len(),
            other => panic!("unexpected {other:?}"),
        }
    }
    let update = transmit(&mut s);
    let increment = varint::encode_to_vec(read as u64);
    assert_eq!(frames(&update), [(id, FrameType::WindowUpdate, increment)]);
    c.handle_input(&update).unwrap();
    assert_eq!(events(&mut c), [Event::Writable(id)]);
    assert_eq!(c.write(id, &data[taken..]).unwrap(), data.len() - taken);
}

#[test]
fn data_beyond_window_from_peer_is_protocol_error() {
    let mut s = Mux::new(Role::Server);
    let chunk = vec![0u8; MAX_DATA];
    let mut wire = raw(1, FrameType::Open, &chunk);
    for _ in 0..INITIAL_WINDOW as usize / MAX_DATA {
        wire.extend(raw(1, FrameType::Data, &chunk));
    }
    assert!(is_protocol_error(s.handle_input(&wire)));
}

#[test]
fn c04_t5_control_and_datagram_go_before_data() {
    let mut c = Mux::new(Role::Client);
    let id = c.open_stream().unwrap();
    c.write(id, &[1; 40 * 1024]).unwrap();
    c.send_control(Bytes::from_static(b"ctl")).unwrap();
    c.send_datagram(Bytes::from_static(b"rtp")).unwrap();
    assert_eq!(
        kinds(&transmit(&mut c)),
        [
            (0, FrameType::Control),
            (0, FrameType::Datagram),
            (id, FrameType::Open),
            (id, FrameType::Data),
            (id, FrameType::Data),
        ]
    );

    // A datagram queued mid-transfer jumps ahead of the remaining DATA.
    let id = c.open_stream().unwrap();
    c.write(id, &[2; 40 * 1024]).unwrap();
    let mut first = Vec::new();
    assert!(c.poll_transmit(&mut first));
    c.send_datagram(Bytes::from_static(b"rtp")).unwrap();
    assert_eq!(
        kinds(&transmit(&mut c)),
        [
            (0, FrameType::Datagram),
            (id, FrameType::Data),
            (id, FrameType::Data),
        ]
    );

    // DATA alternates between streams.
    let (a, b) = (c.open_stream().unwrap(), c.open_stream().unwrap());
    c.write(a, &[3; 2 * MAX_DATA]).unwrap();
    c.write(b, &[4; 2 * MAX_DATA]).unwrap();
    assert_eq!(
        kinds(&transmit(&mut c)),
        [
            (a, FrameType::Open),
            (b, FrameType::Open),
            (a, FrameType::Data),
            (b, FrameType::Data),
        ]
    );
}

#[test]
fn c04_t6_datagram_queue_overflow_drops_the_oldest() {
    let mut c = Mux::new(Role::Client);
    for tag in 0..5u8 {
        c.send_datagram(Bytes::from(vec![tag; 16 * 1024])).unwrap();
    }
    assert_eq!(c.datagram_drops(), 1);
    let tags: Vec<u8> = frames(&transmit(&mut c))
        .iter()
        .map(|(_, _, p)| p[0])
        .collect();
    assert_eq!(tags, [1, 2, 3, 4]);
    assert_eq!(
        c.send_datagram(Bytes::from(vec![0; MAX_DATAGRAM + 1])),
        Err(MuxError::DatagramTooLarge(MAX_DATAGRAM + 1))
    );
}

#[test]
fn c04_t7_client_opens_odd_ids_server_even() {
    let (mut c, mut s) = pair();
    let client: Vec<u64> = (0..3).map(|_| c.open_stream().unwrap()).collect();
    let server: Vec<u64> = (0..2).map(|_| s.open_stream().unwrap()).collect();
    assert_eq!(client, [1, 3, 5]);
    assert_eq!(server, [2, 4]);

    s.write(2, b"push").unwrap();
    pump(&mut c, &mut s);
    // OPEN is queued at open time, so stream 4 reaches the peer too, without data.
    assert_eq!(
        events(&mut c),
        [
            Event::StreamOpened(2),
            Event::Readable(2),
            Event::StreamOpened(4)
        ]
    );

    // OPEN with the receiver's own parity is rejected.
    assert!(is_protocol_error(
        Mux::new(Role::Server).handle_input(&raw(2, FrameType::Open, b""))
    ));
    assert!(is_protocol_error(
        Mux::new(Role::Client).handle_input(&raw(1, FrameType::Open, b""))
    ));
}

#[test]
fn stream_limit_is_enforced_both_ways() {
    let mut c = Mux::new(Role::Client);
    for _ in 0..MAX_STREAMS {
        c.open_stream().unwrap();
    }
    assert_eq!(c.open_stream(), Err(MuxError::StreamLimit));

    let mut s = Mux::new(Role::Server);
    let mut wire = Vec::new();
    for i in 0..=MAX_STREAMS as u64 {
        wire.extend(raw(2 * i + 1, FrameType::Open, b"x"));
    }
    s.handle_input(&wire).unwrap();
    assert_eq!(s.open_streams(), MAX_STREAMS);
    let over = 2 * MAX_STREAMS as u64 + 1;
    assert_eq!(
        frames(&transmit(&mut s)),
        [(over, FrameType::Rst, vec![ErrorCode::STREAM_LIMIT.0 as u8])]
    );
    // Later frames for the refused stream are ignored.
    s.handle_input(&raw(over, FrameType::Data, b"y")).unwrap();
}

#[test]
fn protocol_violations_are_fatal() {
    let opened = raw(1, FrameType::Open, b"");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("never opened", raw(1, FrameType::Data, b"x")),
        ("stream frame on 0", raw(0, FrameType::Data, b"x")),
        ("datagram off 0", raw(1, FrameType::Datagram, b"x")),
        ("unknown type", vec![0x01, 0x07, 0x00]),
        ("FIN with payload", vec![0x01, 0x02, 0x01, 0x00]),
        ("reused id", [opened.clone(), opened.clone()].concat()),
        (
            "DATA after FIN",
            [
                opened.clone(),
                raw(1, FrameType::Fin, b""),
                raw(1, FrameType::Data, b"x"),
            ]
            .concat(),
        ),
        (
            "malformed RST",
            [opened.clone(), raw(1, FrameType::Rst, &[0x05, 0x00])].concat(),
        ),
    ];
    for (name, wire) in cases {
        let mut s = Mux::new(Role::Server);
        let first = s.handle_input(&wire);
        assert!(is_protocol_error(first), "{name}: {first:?}");
        assert_eq!(s.handle_input(b""), first, "{name}: error is sticky");
    }

    // An oversized DATA length is rejected from the header alone.
    let mut header = Vec::new();
    frame::put_varint(1, &mut header);
    header.push(FrameType::Data as u8);
    frame::put_varint(MAX_DATA as u64 + 1, &mut header);
    assert!(is_protocol_error(
        Mux::new(Role::Server).handle_input(&header)
    ));
}

#[test]
fn input_split_at_every_byte_is_parsed() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    c.write(id, b"hello").unwrap();
    c.finish(id).unwrap();
    c.send_datagram(Bytes::from_static(b"dgram")).unwrap();
    for byte in transmit(&mut c) {
        s.handle_input(&[byte]).unwrap();
    }
    assert_eq!(
        events(&mut s),
        [
            Event::Datagram(Bytes::from_static(b"dgram")),
            Event::StreamOpened(id),
            Event::Readable(id),
            Event::Readable(id),
        ]
    );
    assert_eq!(read_all(&mut s, id), (b"hello".to_vec(), true));
}

#[test]
fn window_update_edge_cases() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    c.write(id, &[0; MAX_DATA]).unwrap();
    pump(&mut c, &mut s);
    // Window grew while the writer was not blocked: no Writable.
    c.handle_input(&raw(id, FrameType::WindowUpdate, &[0x10]))
        .unwrap();
    assert!(events(&mut c).is_empty());

    // After FIN no more data can come, so reading sends no WINDOW_UPDATE.
    let big = vec![0; 200 * 1024];
    c.write(id, &big).unwrap();
    c.finish(id).unwrap();
    pump(&mut c, &mut s);
    read_all(&mut s, id);
    assert!(transmit(&mut s).is_empty());
}

#[test]
fn opens_leave_in_id_order() {
    let mut c = Mux::new(Role::Client);
    let (a, b) = (c.open_stream().unwrap(), c.open_stream().unwrap());
    c.write(b, b"b first").unwrap();
    c.write(a, b"a second").unwrap();
    assert_eq!(
        frames(&transmit(&mut c)),
        [
            (a, FrameType::Open, b"a second".to_vec()),
            (b, FrameType::Open, b"b first".to_vec()),
        ]
    );
}

#[test]
fn send_order_puts_rst_and_window_update_before_data() {
    let (mut c, mut s) = pair();
    let (a, b) = (c.open_stream().unwrap(), c.open_stream().unwrap());
    c.write(a, &vec![1; INITIAL_WINDOW as usize / 2]).unwrap();
    s.handle_input(&transmit(&mut c)).unwrap();
    // Server queues DATA, a WINDOW_UPDATE (by reading), an RST, then CONTROL and DATAGRAM.
    s.write(a, &[2; 2 * MAX_DATA]).unwrap();
    read_all(&mut s, a);
    s.reset(b, ErrorCode::NO_ERROR).unwrap();
    s.send_control(Bytes::from_static(b"ctl")).unwrap();
    s.send_datagram(Bytes::from_static(b"dg")).unwrap();
    assert_eq!(
        kinds(&transmit(&mut s)),
        [
            (0, FrameType::Control),
            (0, FrameType::Datagram),
            (a, FrameType::WindowUpdate),
            (b, FrameType::Rst),
            (a, FrameType::Data),
            (a, FrameType::Data),
        ]
    );
}

#[test]
fn stream_limit_slot_frees_on_fin_before_the_app_reads() {
    let (mut c, mut s) = pair();
    let ids: Vec<u64> = (0..MAX_STREAMS).map(|_| c.open_stream().unwrap()).collect();
    pump(&mut c, &mut s);
    events(&mut s);

    // Server finishes first; the client reads that FIN and sends its own.
    let id = ids[0];
    s.finish(id).unwrap();
    c.handle_input(&transmit(&mut s)).unwrap();
    assert_eq!(read_all(&mut c, id), (vec![], true));
    c.finish(id).unwrap();
    let mut wire = transmit(&mut c);
    // The client reopens at once; FIN and OPEN reach the server in one batch,
    // before its app reads the FIN.
    let new = c.open_stream().unwrap();
    wire.extend(transmit(&mut c));
    s.handle_input(&wire).unwrap();
    assert!(
        transmit(&mut s).is_empty(),
        "well-behaved reopen must not be refused"
    );
    assert!(s.streams.contains_key(&new));
}

#[test]
fn reset_with_pending_send_is_skipped_by_the_scheduler() {
    let mut c = Mux::new(Role::Client);
    let (a, b) = (c.open_stream().unwrap(), c.open_stream().unwrap());
    c.write(a, &[1; 3 * MAX_DATA]).unwrap();
    c.write(b, b"b").unwrap();
    let mut first = Vec::new();
    assert!(c.poll_transmit(&mut first));
    c.reset(a, ErrorCode::NO_ERROR).unwrap();
    assert_eq!(
        kinds(&transmit(&mut c)),
        [(a, FrameType::Rst), (b, FrameType::Open)]
    );
}

#[test]
fn one_byte_frames_do_not_amplify_events() {
    let mut s = Mux::new(Role::Server);
    let mut wire = raw(1, FrameType::Open, b"x");
    for _ in 0..1000 {
        wire.extend(raw(1, FrameType::Data, b"y"));
    }
    s.handle_input(&wire).unwrap();
    assert_eq!(events(&mut s), [Event::StreamOpened(1), Event::Readable(1)]);
    assert_eq!(read_all(&mut s, 1).0.len(), 1001);
}

#[test]
fn refused_open_flood_is_fatal() {
    let mut s = Mux::new(Role::Server);
    let mut wire = Vec::new();
    for i in 0..2 * MAX_STREAMS as u64 + 1 {
        wire.extend(raw(2 * i + 1, FrameType::Open, b""));
    }
    // The peer never reads, so refusals are never transmitted.
    assert!(is_protocol_error(s.handle_input(&wire)));
}

#[test]
fn peer_frame_on_unsent_local_stream_is_protocol_error() {
    let mut c = Mux::new(Role::Client);
    let id = c.open_stream().unwrap();
    assert!(is_protocol_error(c.handle_input(&raw(
        id,
        FrameType::Data,
        b"fake reply"
    ))));
}

#[test]
fn more_protocol_violations_are_fatal() {
    let opened = raw(1, FrameType::Open, b"");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("control off 0", raw(1, FrameType::Control, b"x")),
        (
            "WINDOW_UPDATE trailing byte",
            [
                opened.clone(),
                raw(1, FrameType::WindowUpdate, &[0x01, 0x00]),
            ]
            .concat(),
        ),
        (
            "WINDOW_UPDATE overflow",
            [
                opened.clone(),
                raw(
                    1,
                    FrameType::WindowUpdate,
                    &varint::encode_to_vec(varint::MAX),
                ),
            ]
            .concat(),
        ),
        (
            "duplicate FIN",
            [
                opened.clone(),
                raw(1, FrameType::Fin, b""),
                raw(1, FrameType::Fin, b""),
            ]
            .concat(),
        ),
        (
            "lower OPEN after higher",
            [raw(3, FrameType::Open, b""), opened.clone()].concat(),
        ),
    ];
    for (name, wire) in cases {
        let r = Mux::new(Role::Server).handle_input(&wire);
        assert!(is_protocol_error(r), "{name}: {r:?}");
    }
}

#[test]
fn send_buffer_is_capped_even_with_a_huge_window() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    pump(&mut c, &mut s);
    let grant = raw(id, FrameType::WindowUpdate, &varint::encode_to_vec(1 << 40));
    c.handle_input(&grant).unwrap();
    let taken = c.write(id, &vec![0; 1 << 20]).unwrap();
    assert_eq!(taken as u64, SEND_BUFFER);
}

#[test]
fn read_with_zero_max_still_makes_progress() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    c.write(id, b"ab").unwrap();
    pump(&mut c, &mut s);
    assert_eq!(s.read(id, 0), Ok(Read::Data(Bytes::from_static(b"a"))));
}

#[test]
fn stream_limit_slot_frees_on_reset_before_reopen() {
    let (mut c, mut s) = pair();
    let ids: Vec<u64> = (0..MAX_STREAMS).map(|_| c.open_stream().unwrap()).collect();
    pump(&mut c, &mut s);
    events(&mut s);
    c.reset(ids[0], ErrorCode::NO_ERROR).unwrap();
    let new = c.open_stream().unwrap();
    s.handle_input(&transmit(&mut c)).unwrap();
    assert!(
        transmit(&mut s).is_empty(),
        "reopen after RST must not be refused"
    );
    assert!(s.streams.contains_key(&new));
}

#[test]
fn unread_data_keeps_the_slot() {
    let mut s = Mux::new(Role::Server);
    // Each stream: OPEN with data, then FIN; the server finishes its side too.
    for i in 0..MAX_STREAMS as u64 {
        let id = 2 * i + 1;
        s.handle_input(
            &[
                raw(id, FrameType::Open, b"unread"),
                raw(id, FrameType::Fin, b""),
            ]
            .concat(),
        )
        .unwrap();
        s.finish(id).unwrap();
    }
    transmit(&mut s);
    events(&mut s);
    // FIN went both ways, but data is unread: slots stay taken and the next OPEN is refused.
    let over = 2 * MAX_STREAMS as u64 + 1;
    s.handle_input(&raw(over, FrameType::Open, b"")).unwrap();
    assert_eq!(kinds(&transmit(&mut s)), [(over, FrameType::Rst)]);
    assert_eq!(s.open_streams(), MAX_STREAMS);
    // Reading the data frees the slot even before the app reads Finished.
    assert_eq!(
        s.read(1, usize::MAX),
        Ok(Read::Data(Bytes::from_static(b"unread")))
    );
    s.handle_input(&raw(over + 2, FrameType::Open, b""))
        .unwrap();
    assert!(transmit(&mut s).is_empty());
}

#[test]
fn writable_after_send_buffer_drains() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    pump(&mut c, &mut s);
    let grant = raw(id, FrameType::WindowUpdate, &varint::encode_to_vec(1 << 20));
    c.handle_input(&grant).unwrap();
    let taken = c.write(id, &vec![0; 1 << 20]).unwrap();
    assert_eq!(taken as u64, SEND_BUFFER);
    let mut out = Vec::new();
    assert!(c.poll_transmit(&mut out));
    assert_eq!(events(&mut c), [Event::Writable(id)]);
}

#[test]
fn close_read_discards_and_keeps_the_window_open() {
    let (mut c, mut s) = pair();
    let id = c.open_stream().unwrap();
    c.write(id, b"ignored").unwrap();
    pump(&mut c, &mut s);
    s.close_read(id).unwrap();
    events(&mut s);
    // More than a window's worth arrives and is credited back without anyone reading.
    let data = vec![0u8; 3 * INITIAL_WINDOW as usize];
    let mut sent = 0;
    for _ in 0..100 {
        if sent < data.len() {
            sent += c.write(id, &data[sent..]).unwrap();
        }
        pump(&mut c, &mut s);
    }
    assert_eq!(sent, data.len(), "sender stalled");
    assert!(
        events(&mut s)
            .iter()
            .all(|e| !matches!(e, Event::Readable(_)))
    );
    // The server still sends and finishes; after both FINs the stream is gone on both sides.
    s.write(id, b"reply").unwrap();
    s.finish(id).unwrap();
    c.finish(id).unwrap();
    pump(&mut c, &mut s);
    assert_eq!(read_all(&mut c, id), (b"reply".to_vec(), true));
    assert_eq!((c.open_streams(), s.open_streams()), (0, 0));
}

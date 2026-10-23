use super::*;

const SID: u64 = 0x00ab_cdef_0123;

fn device() -> (DeviceId, Token) {
    (DeviceId([0x01; 16]), Token::from_bytes([0x42; 32]))
}

fn uri_for(id: DeviceId, token: Token) -> ConnectionUri {
    ConnectionUri {
        device_id: id,
        token,
        host: "cdn.example.com".into(),
        port: 443,
        sni: None,
        path: "/api/v2/sync".into(),
        pin: None,
        transport: TransportMode::Auto,
        insecure: false,
        passthrough: None,
    }
}

fn registry(revoked: bool) -> HashMap<DeviceId, DeviceRecord> {
    let (id, token) = device();
    let record = DeviceRecord {
        token_hash: token.hash(),
        revoked,
    };
    HashMap::from([(id, record)])
}

fn policy(caps: Caps) -> ServerPolicy {
    ServerPolicy {
        auth_path: "/api/v2/sync".into(),
        caps,
        udp_max: 1200,
    }
}

fn info() -> ClientInfo {
    ClientInfo::new("openwrt", "0.1.0")
}

/// Runs the server side on the client's request.
fn server_side(
    transport: Transport,
    request: &[u8],
    registry: &HashMap<DeviceId, DeviceRecord>,
    policy: &ServerPolicy,
) -> Result<Accepted, AuthFailure> {
    let (req, used) = AuthRequest::decode(transport, request)?.expect("complete request");
    assert_eq!(used, request.len());
    authenticate(&req, registry, policy, SID)
}

const BOTH: [Transport; 2] = [Transport::Quic, Transport::Tls];

#[test]
fn c05_t1_valid_token_establishes_with_agreed_caps_and_sid() {
    for transport in BOTH {
        let (id, token) = device();
        let now = Instant::now();
        let (mut client, request) =
            ClientHandshake::start(transport, &uri_for(id, token), &info(), now).unwrap();
        let accepted =
            server_side(transport, &request, &registry(false), &policy(Caps::ALL)).unwrap();
        assert_eq!(accepted.device, id);
        assert_eq!(accepted.client, info());

        let mut response = accept_response(transport, &accepted.session);
        response.extend_from_slice(b"first control bytes");
        // Feed in two pieces to exercise buffering.
        let (a, b) = response.split_at(response.len() / 2);
        assert_eq!(client.handle_input(a), Ok(None));
        let established = client.handle_input(b).unwrap().unwrap();
        assert_eq!(established.session, accepted.session);
        assert_eq!(established.session.sid, SID);
        assert_eq!(established.session.caps, Caps::ALL);
        assert_eq!(established.session.udp_max, 1200);
        assert_eq!(established.leftover, b"first control bytes");
        // Done: a late deadline no longer fires.
        assert_eq!(client.handle_timeout(now + HANDSHAKE_TIMEOUT), Ok(()));
    }
}

#[test]
fn c05_t2_unknown_device_or_wrong_token_fails() {
    for transport in BOTH {
        let (id, token) = device();
        let start = |uri: &ConnectionUri| {
            ClientHandshake::start(transport, uri, &info(), Instant::now())
                .unwrap()
                .1
        };

        let stranger = uri_for(DeviceId([0x02; 16]), token.clone());
        let result = server_side(
            transport,
            &start(&stranger),
            &registry(false),
            &policy(Caps::ALL),
        );
        assert_eq!(result.unwrap_err(), AuthFailure::UnknownDevice);

        let wrong = uri_for(id, Token::from_bytes([0x43; 32]));
        let result = server_side(
            transport,
            &start(&wrong),
            &registry(false),
            &policy(Caps::ALL),
        );
        assert_eq!(result.unwrap_err(), AuthFailure::BadToken);
    }
}

#[test]
fn c05_t2_client_treats_any_other_answer_as_rejected() {
    let (id, token) = device();
    let uri = uri_for(id, token);
    let masquerade: [(Transport, Vec<u8>); 3] = [
        (
            Transport::Quic,
            h3::encode_response(404, &[("content-type", "text/html")]).to_vec(),
        ),
        (Transport::Quic, h3::encode_response(403, &[]).to_vec()),
        (
            Transport::Tls,
            b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n<html>".to_vec(),
        ),
    ];
    for (transport, answer) in masquerade {
        let (mut client, _) =
            ClientHandshake::start(transport, &uri, &info(), Instant::now()).unwrap();
        assert_eq!(client.handle_input(&answer), Err(HandshakeError::Rejected));
    }
}

#[test]
fn c05_t3_revoked_device_fails() {
    for transport in BOTH {
        let (id, token) = device();
        let request =
            ClientHandshake::start(transport, &uri_for(id, token), &info(), Instant::now())
                .unwrap()
                .1;
        let result = server_side(transport, &request, &registry(true), &policy(Caps::ALL));
        assert_eq!(result.unwrap_err(), AuthFailure::Revoked);
    }
}

#[test]
fn c05_t4_incompatible_version_is_refused_both_ways() {
    let (id, token) = device();
    let uri = uri_for(id, token);
    let mut future = info();
    future.version = 2;
    for transport in BOTH {
        let request = ClientHandshake::start(transport, &uri, &future, Instant::now())
            .unwrap()
            .1;
        let result = server_side(transport, &request, &registry(false), &policy(Caps::ALL));
        assert_eq!(result.unwrap_err(), AuthFailure::UnsupportedVersion);

        // A server answering with a version we do not speak is not trusted either.
        let (mut client, _) =
            ClientHandshake::start(transport, &uri, &info(), Instant::now()).unwrap();
        let session = SessionInfo {
            version: 2,
            caps: Caps::ALL,
            sid: 1,
            udp_max: 1200,
        };
        assert_eq!(
            client.handle_input(&accept_response(transport, &session)),
            Err(HandshakeError::Malformed)
        );
    }
}

#[test]
fn c05_t5_caps_are_the_intersection() {
    let (id, token) = device();
    let uri = uri_for(id, token);
    let mut offer = info();
    // Includes a bit from a future version that this server does not know.
    offer.caps = Caps::FAST_OPEN | Caps::UDP | Caps(1 << 5);
    for transport in BOTH {
        let (mut client, request) =
            ClientHandshake::start(transport, &uri, &offer, Instant::now()).unwrap();
        let accepted = server_side(
            transport,
            &request,
            &registry(false),
            &policy(Caps::UDP | Caps::PADDING),
        )
        .unwrap();
        assert_eq!(accepted.session.caps, Caps::UDP);
        let established = client
            .handle_input(&accept_response(transport, &accepted.session))
            .unwrap()
            .unwrap();
        assert_eq!(established.session.caps, Caps::UDP);

        // Granting something never offered is a broken server.
        let (mut client, _) =
            ClientHandshake::start(transport, &uri, &offer, Instant::now()).unwrap();
        let session = SessionInfo {
            caps: Caps::PADDING,
            ..accepted.session
        };
        assert_eq!(
            client.handle_input(&accept_response(transport, &session)),
            Err(HandshakeError::Malformed)
        );
    }
}

#[test]
fn handshake_times_out_without_an_answer() {
    let (id, token) = device();
    let now = Instant::now();
    let (mut client, _) =
        ClientHandshake::start(Transport::Quic, &uri_for(id, token), &info(), now).unwrap();
    assert_eq!(client.deadline(), now + HANDSHAKE_TIMEOUT);
    assert_eq!(client.handle_timeout(now + Duration::from_secs(9)), Ok(()));
    assert_eq!(
        client.handle_timeout(client.deadline()),
        Err(HandshakeError::Timeout)
    );
}

#[test]
fn malformed_requests_go_to_the_masquerade() {
    let auth = authorization(&device().0, &device().1);
    let client = info().to_header();
    let good = [
        ("authorization", auth.as_str()),
        ("x-client", client.as_str()),
    ];
    let h3_cases: Vec<Zeroizing<Vec<u8>>> = vec![
        h3::encode_request("a", "/api/v2/sync", &good[..1]),
        h3::encode_request("a", "/api/v2/sync", &[good[0], good[0], good[1]]),
        h3::encode_request("a", "/api/v2/sync", &[good[0], ("x-client", "v=1")]),
        h3::encode_request(
            "a",
            "/api/v2/sync",
            &[("authorization", "Basic abc"), good[1]],
        ),
        h3::encode_request("a", "/api/v2/sync", &[good[0], good[1], (":path", "/late")]),
    ];
    for wire in &h3_cases {
        let result = AuthRequest::decode(Transport::Quic, wire)
            .and_then(|r| authenticate(&r.unwrap().0, &registry(false), &policy(Caps::ALL), SID));
        assert_eq!(result.unwrap_err(), AuthFailure::Malformed);
    }
    // A plain browser request: not an upgrade.
    let browser = b"GET /api/v2/sync HTTP/1.1\r\nHost: a\r\n\r\n";
    assert_eq!(
        AuthRequest::decode(Transport::Tls, browser).unwrap_err(),
        AuthFailure::Malformed
    );
    // Right credentials, wrong path.
    let wire = http1::encode_request("a", "/index.html", &good);
    let (req, _) = AuthRequest::decode(Transport::Tls, &wire).unwrap().unwrap();
    let result = authenticate(&req, &registry(false), &policy(Caps::ALL), SID);
    assert_eq!(result.unwrap_err(), AuthFailure::WrongPath);
}

#[test]
fn c05_t8_auth_request_debug_hides_the_token() {
    let (id, token) = device();
    let secret = token.to_base64url();
    let (_, request) =
        ClientHandshake::start(Transport::Tls, &uri_for(id, token), &info(), Instant::now())
            .unwrap();
    let (req, _) = AuthRequest::decode(Transport::Tls, &request)
        .unwrap()
        .unwrap();
    assert!(!format!("{req:?}").contains(secret.as_str()));
}

#[test]
fn header_values_are_strict() {
    assert_eq!(ClientInfo::parse(&info().to_header()), Some(info()));
    let bad_client = [
        "v=1; caps=7; plat=openwrt",
        "v=1; caps=7; plat=openwrt; ver=0.1; ver=0.2",
        "v=1; caps=0x7; plat=openwrt; ver=0.1",
        "v=1; caps=7F; plat=openwrt; ver=0.1",
        "v=+1; caps=7; plat=openwrt; ver=0.1",
        "v=1; caps=7; plat=open wrt; ver=0.1",
        "v=1;; caps=7; plat=openwrt; ver=0.1",
    ];
    for s in bad_client {
        assert_eq!(ClientInfo::parse(s), None, "{s}");
    }
    let session = SessionInfo {
        version: 1,
        caps: Caps::ALL,
        sid: u64::MAX,
        udp_max: 65_507,
    };
    assert_eq!(
        session.to_header(),
        "v=1; caps=7; sid=ffffffffffffffff; udp-max=65507"
    );
    assert_eq!(SessionInfo::parse(&session.to_header()), Some(session));
    assert_eq!(
        SessionInfo::parse("v=1; caps=7; sid=1ffffffffffffffff; udp-max=1"),
        None
    );
}

#[test]
fn huffman_coded_session_header_is_accepted() {
    // What an HTTP/3 stack such as the h3 crate sends: indexed :status, Huffman literals.
    let (id, token) = device();
    let (mut client, _) = ClientHandshake::start(
        Transport::Quic,
        &uri_for(id, token),
        &info(),
        Instant::now(),
    )
    .unwrap();
    let value = "v=1; caps=3; sid=ab; udp-max=1200";
    let (name, value_h) = (h3::huffman_encode("x-session"), h3::huffman_encode(value));
    let mut block = vec![0x00, 0x00, 0xd9]; // :status 200 from the static table.
    // Literal name, Huffman; the 3-bit length prefix overflows at 7 (RFC 7541 §5.1).
    match name.len() {
        n @ 0..7 => block.push(0x28 | n as u8),
        n => block.extend_from_slice(&[0x2f, (n - 7) as u8]),
    }
    block.extend_from_slice(&name);
    block.push(0x80 | value_h.len() as u8); // Value, Huffman.
    block.extend_from_slice(&value_h);
    let mut response = vec![0x01, block.len() as u8];
    response.extend_from_slice(&block);
    let established = client.handle_input(&response).unwrap().unwrap();
    assert_eq!(established.session.sid, 0xab);
    assert_eq!(established.session.caps, Caps::FAST_OPEN | Caps::UDP);
}

#[test]
fn handshake_remembers_how_it_ended() {
    let (id, token) = device();
    let uri = uri_for(id, token);
    let (mut client, _) =
        ClientHandshake::start(Transport::Tls, &uri, &info(), Instant::now()).unwrap();
    let rejected = b"HTTP/1.1 404 Not Found\r\n\r\n";
    assert_eq!(client.handle_input(rejected), Err(HandshakeError::Rejected));
    assert_eq!(client.handle_input(b"more"), Err(HandshakeError::Rejected));

    let (mut client, _) =
        ClientHandshake::start(Transport::Tls, &uri, &info(), Instant::now()).unwrap();
    let session = SessionInfo {
        version: 1,
        caps: Caps::UDP,
        sid: 1,
        udp_max: 1200,
    };
    assert!(
        client
            .handle_input(&accept_response(Transport::Tls, &session))
            .unwrap()
            .is_some()
    );
    assert_eq!(client.handle_input(b"mux"), Err(HandshakeError::Finished));

    // A 101 without the upgrade headers is not a real switch.
    let (mut client, _) =
        ClientHandshake::start(Transport::Tls, &uri, &info(), Instant::now()).unwrap();
    let bare = format!(
        "HTTP/1.1 101 Switching Protocols\r\nx-session: {}\r\n\r\n",
        session.to_header()
    );
    assert_eq!(
        client.handle_input(bare.as_bytes()),
        Err(HandshakeError::Malformed)
    );
}

#[test]
fn request_injection_is_refused() {
    let (id, token) = device();
    let mut uri = uri_for(id, token);
    uri.path = "/x HTTP/1.1\r\nEvil: 1\r\nX:".into();
    let start = |uri: &ConnectionUri, info: &ClientInfo| {
        ClientHandshake::start(Transport::Tls, uri, info, Instant::now()).map(|_| ())
    };
    assert_eq!(start(&uri, &info()), Err(HandshakeError::InvalidInput));
    let uri = uri_for(device().0, device().1);
    let evil = ClientInfo::new("openwrt\r\nEvil: 1", "0.1.0");
    assert_eq!(start(&uri, &evil), Err(HandshakeError::InvalidInput));
}

/// Fastest of many batches of `authenticate` calls; the minimum filters out scheduler noise.
fn fastest_auth(request: &AuthRequest, registry: &HashMap<DeviceId, DeviceRecord>) -> u128 {
    let policy = policy(Caps::ALL);
    (0..30)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..200 {
                let _ = std::hint::black_box(authenticate(request, registry, &policy, SID));
            }
            start.elapsed().as_nanos()
        })
        .min()
        .unwrap()
}

#[test]
fn c05_t7_unknown_device_wrong_token_and_wrong_path_cost_the_same() {
    // Without the dummy hash, the unknown-device and wrong-path paths would skip SHA-256 and run
    // several times faster. This cannot catch a leak inside the compare itself (memcmp-style);
    // that is what `subtle` is for, see `secret::tests`.
    let (id, token) = device();
    let request = |uri: &ConnectionUri| {
        let wire = ClientHandshake::start(Transport::Tls, uri, &info(), Instant::now())
            .unwrap()
            .1;
        AuthRequest::decode(Transport::Tls, &wire)
            .unwrap()
            .unwrap()
            .0
    };
    let unknown = request(&uri_for(DeviceId([0x02; 16]), token.clone()));
    let wrong_token = request(&uri_for(id, Token::from_bytes([0x43; 32])));
    let mut wrong_path = uri_for(id, token);
    wrong_path.path = "/index.html".into();
    let wrong_path = request(&wrong_path);
    let registry = registry(false);
    fastest_auth(&unknown, &registry);
    let mut times = [0u128; 3];
    for _ in 0..5 {
        times[0] += fastest_auth(&unknown, &registry);
        times[1] += fastest_auth(&wrong_token, &registry);
        times[2] += fastest_auth(&wrong_path, &registry);
    }
    let (min, max) = (times.iter().min().unwrap(), times.iter().max().unwrap());
    assert!(
        *max as f64 / *min as f64 <= 1.5,
        "unknown device / wrong token / wrong path: {times:?} ns"
    );
}

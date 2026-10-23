//! Client side of the auth exchange: whatever a server or middlebox answers.

#![no_main]

use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use proto::auth::{
    ClientHandshake, ClientInfo, ConnectionUri, DeviceId, Token, Transport, TransportMode,
};

fuzz_target!(|data: &[u8]| {
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
        let (a, b) = data.split_at(data.len() / 3);
        if let Ok(None) = client.handle_input(a) {
            let _ = client.handle_input(b);
        }
    }
});

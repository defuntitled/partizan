//! Server side of the auth exchange: whatever an unauthenticated prober sends.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use proto::auth::{
    AuthRequest, Caps, DeviceId, DeviceRecord, ServerPolicy, Token, Transport, authenticate,
};

fuzz_target!(|data: &[u8]| {
    let registry = HashMap::from([(
        DeviceId([1; 16]),
        DeviceRecord {
            token_hash: Token::from_bytes([2; 32]).hash(),
            revoked: false,
        },
    )]);
    let policy = ServerPolicy {
        auth_path: "/api/v2/sync".into(),
        caps: Caps::ALL,
        udp_max: 1200,
    };
    for transport in [Transport::Quic, Transport::Tls] {
        if let Ok(Some((request, used))) = AuthRequest::decode(transport, data) {
            assert!(used <= data.len());
            let _ = authenticate(&request, &registry, &policy, 1);
        }
    }
});

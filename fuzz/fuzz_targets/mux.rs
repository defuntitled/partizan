//! Mux input from a hostile peer, on both sides, then everything the app would do with it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::mux::{Event, Mux, Read, Role};

fuzz_target!(|data: &[u8]| {
    for role in [Role::Client, Role::Server] {
        let mut mux = Mux::new(role);
        // Split the input in two to exercise partial frames.
        let (a, b) = data.split_at(data.len() / 2);
        for chunk in [a, b] {
            if mux.handle_input(chunk).is_err() {
                break;
            }
            while let Some(event) = mux.poll_event() {
                if let Event::Readable(id) | Event::StreamOpened(id) = event {
                    while let Ok(Read::Data(_)) = mux.read(id, 4096) {}
                    let _ = mux.write(id, b"reply");
                }
            }
            let mut out = Vec::new();
            while mux.poll_transmit(&mut out) {}
        }
    }
});

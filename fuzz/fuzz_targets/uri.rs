//! Connection URI parsing; a parsed URI must survive formatting and parsing again.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proto::auth::ConnectionUri;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(uri) = ConnectionUri::parse(s) {
        let again = ConnectionUri::parse(&uri.to_uri_string()).expect("formatted URI parses");
        assert_eq!(format!("{again:?}"), format!("{uri:?}"));
    }
});

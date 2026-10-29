//! `cargo run -p uniffi-bindgen -- generate --library <lib> --language kotlin --out-dir <dir>`:
//! foreign bindings for `client-ffi`, kept out of its own dependency tree.

fn main() {
    uniffi::uniffi_bindgen_main()
}

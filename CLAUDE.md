# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## State of the repo

Specs are in `spec/` (in Russian). `spec/partizan_spec.md` is the source of truth for protocol, formats, and constants; `spec/partizan — decompozition.md` is the commit-by-commit plan (C01–C26) with per-commit DoD and test cases. Implement commits in that order; check the relevant spec section before writing code rather than guessing wire formats or limits.

## Checks (must pass on every commit)

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo test -p <crate> c07_t3   # single test case by ID
```

Every commit must build and pass tests on its own (`git bisect` must work).

## Commit and test conventions

- Conventional Commits: `feat(proto): codec for Connect frames`. Commit body names the plan number (`C07`) and the spec sections it implements.
- Test names embed the case ID from the plan: `fn c07_t3_auth_rejects_unknown_device()`. Manual cases are marked «ручной» and their result goes in the commit message.
- If a commit changes behavior described in the spec, update the spec in the same commit.
- Public items are documented; no `TODO` without an issue link.

## Architectural constraints

- `proto` is sans-io: no tokio, sockets, or clocks (time is passed in). It must build unchanged for Android/iOS. Mux state machine lives here and is tested by stepping, not over a network.
- `client-core` takes abstract `TcpRequest` / `UdpPacket`; it must not know about SOCKS5 (future TUN sources plug in instead).
- `#![forbid(unsafe_code)]` in `proto` and `client-core`.
- Own mux in `proto` — do not pull in `yamux`. CONTROL and DATAGRAM frames are always scheduled before DATA.
- TLS: server uses `rustls` with the `ring` provider (never `aws-lc-rs`); client TLS moves to BoringSSL (`boring`) in C21/C22 for Chrome fingerprinting.
- Client binary budget is ≤ 5 MB stripped static musl (CI fails otherwise): on the client use `lexopt` (not `clap`) and `log` + a mini logger (not `tracing`); keep tokio features minimal.
- QUIC 0-RTT stays disabled. Congestion control is Cubic; don't use quinn's BBR.

## Security rules for code

- Secrets live in `Zeroize` types with no `Debug` impl; tokens compared in constant time only.
- Every length read from the network is checked against an upper bound before allocating.
- Never log tokens; destination addresses only at `debug` level.
- Auth failure must never return an error to the peer — the request goes to the masquerade site instead.

## Build targets

```
cargo build --release -p server                          # server, opt-level 3
cargo build --profile release-client -p client-openwrt   # router client, size-optimized (bin `partizan`)
# Cross builds need zig on PATH (0.14.1) and cargo-zigbuild:
cargo zigbuild --profile release-client -p client-openwrt --target aarch64-unknown-linux-musl
cargo zigbuild --release -p server --target x86_64-unknown-linux-musl
scripts/check-size.sh target/aarch64-unknown-linux-musl/release-client/partizan 5242880
```

The client's TCP+TLS runs on BoringSSL (`transport` feature `chrome`, pulled in by `client-core`): building needs cmake, a C/C++ compiler and libclang. If bindgen cannot find `stddef.h`, set `LIBCLANG_PATH` and `BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/<ver>/include`; cross builds also need `BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_musl` pointing at zig's musl headers (see the CI `cross` job). The Chrome profile and its expected JA4 live in `crates/transport/src/chrome.rs`; the JA4 test fails when they drift.

Android library (A04): `scripts/build-android.sh` builds `client-ffi` for `aarch64-linux-android` with `cargo-ndk` (`release-ffi` profile: size-optimized but panics unwind, so UniFFI raises them as exceptions) and packs `target/android/partizan-core.aar` without Gradle. It needs `ANDROID_NDK_HOME` and `cargo install cargo-ndk --version 4.1.2`. `scripts/ffi-kotlin-test.sh` runs the JVM test of the Kotlin bindings (A03). Both fetch `kotlinc` and JNA into `target/tools` (pinned SHA-256). Bindings are generated from the host build: stripped libraries carry no UniFFI metadata.

Size flags (`lto`, `panic = "abort"`, …) live in the `release-client` profile, not `release`, because Cargo can't set them per package.

Toolchain pinned in `rust-toolchain.toml`. Targets: `aarch64-unknown-linux-musl` (router, Routerich AX3000 / OpenWrt 24.10 `mediatek/filogic`) and `x86_64-unknown-linux-musl` (server), cross-built with `cargo-zigbuild`.

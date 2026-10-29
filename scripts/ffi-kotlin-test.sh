#!/usr/bin/env bash
# A03: generates the Kotlin bindings for the host build of client-ffi, compiles them together
# with crates/client-ffi/tests/kotlin/FfiTest.kt and runs the test on the JVM.
# Needs java on PATH; the Kotlin compiler and JNA come from scripts/android-tools.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
. scripts/android-tools.sh

cargo build -p client-ffi
out=target/kotlin-test
rm -rf "$out"
cargo run -q -p uniffi-bindgen -- generate --library target/debug/libclient_ffi.so \
    --language kotlin --no-format --out-dir "$out/src"
"$KOTLINC" "$out/src" crates/client-ffi/tests/kotlin/FfiTest.kt -cp "$JNA_JAR" \
    -include-runtime -nowarn -d "$out/ffi-test.jar"
java --enable-native-access=ALL-UNNAMED -Djna.library.path="$root/target/debug" \
    -cp "$out/ffi-test.jar:$JNA_JAR" partizan.core.test.FfiTestKt

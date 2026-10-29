#!/usr/bin/env bash
# A04: builds client-ffi for Android and packs it with its Kotlin bindings into an AAR:
# target/android/partizan-core.aar. Needs the NDK (ANDROID_NDK_HOME), cargo-ndk, cmake and
# java; the Kotlin compiler and JNA come from scripts/android-tools.sh.
#
# The app adds the AAR and JNA's Android build: implementation("net.java.dev.jna:jna:<v>@aar").
# Only arm64-v8a for now; more ABIs are more `-t` flags and nothing else here changes.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
. scripts/android-tools.sh

ABIS=(arm64-v8a)
# Lowest Android version the library links against (7.0).
API_LEVEL=24
# Kotlin language and API level of the classes, so older Kotlin compilers in apps read them.
KOTLIN_LEVEL=2.2
# Size budget for one ABI's library, bytes (spec: tracked in CI).
SO_BUDGET=8388608

out=target/android
stage=$out/aar
rm -rf "$out"
mkdir -p "$stage/jni"

targets=()
for abi in "${ABIS[@]}"; do targets+=(-t "$abi"); done
cargo ndk "${targets[@]}" -P "$API_LEVEL" -o "$stage/jni" --link-libcxx-shared \
    build --profile release-ffi -p client-ffi
# The NDK's libc++ comes with its symbol table; ours is stripped by the profile.
strip=$(echo "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-strip)
for abi in "${ABIS[@]}"; do "$strip" --strip-unneeded "$stage/jni/$abi/libc++_shared.so"; done

# The stripped libraries carry no UniFFI metadata; the bindings are the same for every target,
# so they come from a host build.
cargo build -q -p client-ffi
cargo run -q -p uniffi-bindgen -- generate --library target/debug/libclient_ffi.so \
    --language kotlin --no-format --out-dir "$out/kotlin"
"$KOTLINC" "$out/kotlin" -cp "$JNA_JAR" -jvm-target 1.8 \
    -language-version "$KOTLIN_LEVEL" -api-version "$KOTLIN_LEVEL" -nowarn \
    -d "$stage/classes.jar"

cat > "$stage/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="partizan.core">
    <uses-sdk android:minSdkVersion="24" />
</manifest>
EOF
# Consumer rules: JNA and the bindings are reached by reflection and by name from native code.
cat > "$stage/proguard.txt" <<'EOF'
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-keep class partizan.core.** { *; }
-dontwarn java.awt.**
EOF
: > "$stage/R.txt"
(cd "$stage" && zip -qr -X ../partizan-core.aar AndroidManifest.xml classes.jar proguard.txt R.txt jni)
aar=$out/partizan-core.aar

# A04-T3: the AAR holds the libraries and the Kotlin API.
listing=$(unzip -l "$aar")
for abi in "${ABIS[@]}"; do
    for so in libclient_ffi.so libc++_shared.so; do
        grep -q "jni/$abi/$so" <<<"$listing" || { echo "missing jni/$abi/$so" >&2; exit 1; }
    done
done
classes=$(unzip -l "$stage/classes.jar")
grep -q "partizan/core/Client_ffiKt.class" <<<"$classes" \
    || { echo "Kotlin API missing from classes.jar" >&2; exit 1; }

# A04-T4: library sizes into the log and the CI summary.
report="| ABI | libclient_ffi.so | libc++_shared.so |
| --- | ---: | ---: |"
for abi in "${ABIS[@]}"; do
    size=$(wc -c < "$stage/jni/$abi/libclient_ffi.so")
    cxx=$(wc -c < "$stage/jni/$abi/libc++_shared.so")
    report+="
| $abi | $size | $cxx |"
    scripts/check-size.sh "$stage/jni/$abi/libclient_ffi.so" "$SO_BUDGET"
done
echo "$report"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '### Android native library size (bytes)\n\n%s\n' "$report" >> "$GITHUB_STEP_SUMMARY"
fi
echo "built $aar ($(wc -c < "$aar") bytes)"

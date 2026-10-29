#!/usr/bin/env bash
# Sourced by the FFI and Android scripts: fetches the Kotlin compiler and JNA into
# target/tools (pinned versions, SHA-256 checked) and exports KOTLINC and JNA_JAR.
# A `kotlinc` already on PATH is used as is.
set -euo pipefail

KOTLIN_VERSION=2.4.21
KOTLIN_SHA256=7cc140e76daf416a0424a5557f99afd7ca89ebd463ea1101261e3e01c33e75cd
JNA_VERSION=5.19.1
JNA_SHA256=4fb141dd8ef6b0585ffceea4bc49602fbc6312fa977e2c488794ea3e6aafecae

tools_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tools=$tools_root/target/tools
mkdir -p "$tools"

# fetch URL FILE SHA256
fetch() {
    local file=$tools/$2
    if [ ! -f "$file" ] || ! echo "$3  $file" | sha256sum -c --status; then
        curl -sSfL "$1" -o "$file.part"
        if ! echo "$3  $file.part" | sha256sum -c --status; then
            echo "checksum mismatch for $1" >&2
            rm -f "$file.part"
            return 1
        fi
        mv "$file.part" "$file"
    fi
}

fetch "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VERSION/jna-$JNA_VERSION.jar" \
    "jna-$JNA_VERSION.jar" "$JNA_SHA256"
JNA_JAR=$tools/jna-$JNA_VERSION.jar

if command -v kotlinc >/dev/null; then
    KOTLINC=$(command -v kotlinc)
else
    fetch "https://github.com/JetBrains/kotlin/releases/download/v$KOTLIN_VERSION/kotlin-compiler-$KOTLIN_VERSION.zip" \
        "kotlin-compiler-$KOTLIN_VERSION.zip" "$KOTLIN_SHA256"
    if [ ! -x "$tools/kotlinc-$KOTLIN_VERSION/bin/kotlinc" ]; then
        rm -rf "$tools/kotlinc-$KOTLIN_VERSION" "$tools/kotlinc"
        unzip -q "$tools/kotlin-compiler-$KOTLIN_VERSION.zip" -d "$tools"
        mv "$tools/kotlinc" "$tools/kotlinc-$KOTLIN_VERSION"
    fi
    KOTLINC=$tools/kotlinc-$KOTLIN_VERSION/bin/kotlinc
fi

export KOTLINC JNA_JAR

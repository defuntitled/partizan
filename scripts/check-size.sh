#!/bin/sh
# Fails when a binary is over its size budget (spec N5: client <= 5 MB).
# usage: check-size.sh BINARY MAX_BYTES
set -eu
size=$(wc -c < "$1")
echo "$1: $size bytes (budget $2)"
if [ "$size" -gt "$2" ]; then
    echo "over budget by $((size - $2)) bytes" >&2
    exit 1
fi

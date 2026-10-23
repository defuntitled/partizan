#!/bin/sh
# Runs the init script with OpenWrt's UCI and procd helpers stubbed and checks what it asks
# procd to run. Usage: sh test-init.sh (exit status 0 on success).
set -eu
dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

config_load() { :; }
config_get() {
	eval "val=\${UCI_$3-}"
	[ -n "$val" ] || val=${4-}
	eval "$1=\$val"
}
config_get_bool() {
	config_get "$@"
	eval "v=\$$1"
	case "$v" in 1|on|true|yes|enabled) eval "$1=1" ;; *) eval "$1=0" ;; esac
}
procd_open_instance() { CMD=''; RESPAWN=''; OPENED=1; }
procd_set_param() {
	key=$1; shift
	case "$key" in command) CMD="$*" ;; respawn) RESPAWN="$*" ;; esac
}
procd_append_param() { key=$1; shift; [ "$key" = command ] && CMD="$CMD $*"; }
procd_close_instance() { :; }
procd_add_reload_trigger() { TRIGGER=$1; }

PARTIZAN_RUN_DIR=$tmp
. "$dir/partizan/files/partizan.init"

# Disabled: nothing starts.
OPENED=0; UCI_enabled=0; UCI_uri='partizan://x'
start_service
[ "$OPENED" -eq 0 ] || fail "started while disabled"

# Enabled without a URI: refuses.
UCI_enabled=1; UCI_uri=''
if start_service 2>/dev/null; then fail "started without a uri"; fi

# Enabled: the token goes to a 0600 file, not to the command line.
UCI_uri='partizan://id:secret-token@cdn.example.com:443?path=/x'
UCI_socks_listen='127.0.0.1:1081'
start_service
case "$CMD" in *secret-token*) fail "token on the command line: $CMD" ;; esac
expected="/usr/bin/partizan run --uri-file $tmp/partizan.uri --socks 127.0.0.1:1081 --log-level info --admin-sock $tmp/partizan.sock"
[ "$CMD" = "$expected" ] || fail "command: $CMD"
[ "$(cat "$tmp/partizan.uri")" = "$UCI_uri" ] || fail "uri file content"
[ "$(stat -c %a "$tmp/partizan.uri")" = 600 ] || fail "uri file mode $(stat -c %a "$tmp/partizan.uri")"
[ -n "$RESPAWN" ] || fail "no respawn"

# honest_connect adds the flag.
UCI_honest_connect=1
start_service
case "$CMD" in *" --honest-connect") ;; *) fail "no --honest-connect: $CMD" ;; esac

service_triggers
[ "$TRIGGER" = partizan ] || fail "reload trigger"
stop_service
[ ! -e "$tmp/partizan.uri" ] || fail "uri file left after stop"
echo "init script OK"

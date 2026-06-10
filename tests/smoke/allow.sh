#!/bin/bash
# Manual approvals: `linprov allow [--once] <token>` permits a blocked exec
# by the token in its BLOCKED-EXEC line, via the daemon control socket.
# --once is transient (in-memory, survives SIGHUP, gone on restart, never
# written to the file); plain allow persists to the allowlist.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

FAILED=0
ALLOW=/tmp/linprov-smoke/allow
LOG=/tmp/linprov-smoke/daemon.log

# check <label> <pass|block> <binary>
check() {
    local label=$1 expect=$2 bin=$3 got
    if "$bin" >/dev/null 2>&1; then got=pass; else got=block; fi
    if [ "$got" = "$expect" ]; then
        echo "  OK   $label ($got)"
    else
        echo "  FAIL $label (got $got, expected $expect)"
        FAILED=1
    fi
}

# Newest token from a BLOCKED-* line in the daemon log.
last_token() {
    grep -oE '\[allow: [0-9a-f]+\]' "$LOG" | tail -1 | grep -oE '[0-9a-f]{8}'
}

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe
start_http_server /tmp/linprov-smoke

sudo bash -c "echo '' > $ALLOW"
start_daemon enforce "$ALLOW" "$LOG" || exit 1
fetch probe

echo "=== blocked exec emits an [allow: token] ==="
check "probe (empty allowlist)" block /tmp/probe
sleep 1
TOKEN=$(last_token)
if [ -n "$TOKEN" ]; then echo "  OK   token emitted: $TOKEN"; else echo "  FAIL no [allow: token] in log"; FAILED=1; fi

echo "=== allow --once: permits live, NOT written to the file ==="
if sudo "$LINPROV_BIN" allow --once "$TOKEN"; then echo "  OK   allow --once accepted"; else echo "  FAIL allow --once rejected"; FAILED=1; fi
check "probe (after --once)" pass /tmp/probe
if grep -q '/tmp/probe' "$ALLOW"; then echo "  FAIL rule written to file (should be transient)"; FAILED=1; else echo "  OK   rule absent from allowlist file"; fi

echo "=== transient survives SIGHUP reload ==="
sudo pkill -HUP -x linprov; sleep 1
check "probe (after SIGHUP)" pass /tmp/probe

echo "=== transient gone after daemon restart ==="
start_daemon enforce "$ALLOW" "$LOG" || exit 1
check "probe (after restart)" block /tmp/probe
sleep 1
TOKEN=$(last_token)

echo "=== allow (persistent): permits live AND writes to the file ==="
if sudo "$LINPROV_BIN" allow "$TOKEN"; then echo "  OK   allow accepted"; else echo "  FAIL allow rejected"; FAILED=1; fi
check "probe (after persistent allow)" pass /tmp/probe
if grep -q '/tmp/probe' "$ALLOW"; then echo "  OK   rule persisted to allowlist file"; else echo "  FAIL rule not in allowlist file"; FAILED=1; fi

cleanup_all
exit "$FAILED"

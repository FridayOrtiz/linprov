#!/bin/bash
# Hot reload: SIGHUP re-parses the allowlist file and re-seeds the BPF
# rules map live — a rule appended (or removed) after launch takes effect
# without restarting the daemon or re-attaching the LSM hooks.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

FAILED=0

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

sighup_daemon() {
    sudo pkill -HUP -x linprov
    sleep 1
}

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe-a
cp -f /bin/true /tmp/linprov-smoke/probe-b
start_http_server /tmp/linprov-smoke

# Start enforcing with only probe-a permitted.
sudo bash -c 'echo "target_filename=/tmp/probe-a" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log || exit 1
fetch_all probe-a probe-b

echo "=== before reload: probe-a permitted, probe-b blocked ==="
check "probe-a" pass  /tmp/probe-a
check "probe-b" block /tmp/probe-b

echo "=== append probe-b rule + SIGHUP (no restart) ==="
sudo bash -c 'echo "target_filename=/tmp/probe-b" >> /tmp/linprov-smoke/allow'
sighup_daemon
if grep -q 'reloading allowlist' /tmp/linprov-smoke/daemon.log; then
    echo "  OK   reload logged"
else
    echo "  FAIL no 'reloading allowlist' line"; FAILED=1
fi
check "probe-a" pass /tmp/probe-a
check "probe-b" pass /tmp/probe-b

echo "=== shrink: drop probe-b rule + SIGHUP -> probe-b blocked again ==="
# Tests the tail-clearing path (count 2 -> 1; stale slot must go inert).
sudo bash -c 'echo "target_filename=/tmp/probe-a" > /tmp/linprov-smoke/allow'
sighup_daemon
check "probe-a" pass  /tmp/probe-a
check "probe-b" block /tmp/probe-b

cleanup_all
exit "$FAILED"

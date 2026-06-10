#!/bin/bash
# An over-capacity allowlist must NOT crash-loop the daemon. A long soak
# run can grow list.allow past MAX_RULES; the daemon must still come up,
# load the first MAX_RULES, warn, and keep enforcing.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

FAILED=0

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe
start_http_server /tmp/linprov-smoke

# Well over MAX_RULES (8192) unique rules. The very first rule permits
# /tmp/probe, so it falls inside the loaded prefix.
N=8300
sudo bash -c "{ echo 'target_filename=/tmp/probe'; for i in \$(seq 1 $N); do echo \"target_filename=/tmp/x\$i\"; done; } > /tmp/linprov-smoke/allow"
echo "=== start daemon with $((N + 1))-rule (over-capacity) allowlist ==="
if start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log; then
    echo "  OK   daemon started (no crash-loop)"
else
    echo "  FAIL daemon did not start"
    exit 1
fi

if grep -qE 'exceeds the BPF map capacity' /tmp/linprov-smoke/daemon.log; then
    echo "  OK   over-capacity warning logged"
else
    echo "  FAIL no over-capacity warning"; FAILED=1
fi

# A rule inside the loaded prefix still enforces.
fetch probe
if /tmp/probe; then
    echo "  OK   first-bucket rule still permits"
else
    echo "  FAIL probe was blocked"; FAILED=1
fi

cleanup_all
exit "$FAILED"

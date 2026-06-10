#!/bin/bash
# Pseudo-fs files (/dev, /proc, /sys, /run) must never be marked. A
# net-touched process writing to /dev/null (every shell redirect does)
# would otherwise mark its inode in-kernel, and then any interpreter
# reading /dev/null (every shell) gets -EPERM in enforce mode — which
# wedges the whole box. Regression for the eBPF write-branch pseudo-fs skip.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

FAILED=0
LOG=/tmp/linprov-smoke/daemon.log
cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe
start_http_server /tmp/linprov-smoke
sudo bash -c 'echo "" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow "$LOG" || exit 1

echo "=== a net-touched process writes to /dev/null (would mark it pre-fix) ==="
# curl connects to localhost (→ marked) AND writes to /dev/null.
curl -fsS -o /dev/null "http://127.0.0.1:$LINPROV_HTTP_PORT/probe"
sleep 1

echo "=== an interpreter reading /dev/null must NOT be blocked ==="
if bash -c '. /dev/null'; then
    echo "  OK   bash sources /dev/null (pseudo-fs not marked)"
else
    echo "  FAIL bash blocked reading /dev/null (pseudo-fs got marked)"; FAILED=1
fi
if grep -q 'BLOCKED-SCRIPT script=/dev/null' "$LOG"; then
    echo "  FAIL daemon blocked an interpreter reading /dev/null"; FAILED=1
else
    echo "  OK   no /dev/null interpreter block logged"
fi

cleanup_all
exit "$FAILED"

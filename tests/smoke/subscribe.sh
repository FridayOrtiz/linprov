#!/bin/bash
# Control-socket `subscribe`: a client subscribes and receives a BLOCK
# event (token + path) when an exec is blocked — the daemon side of the
# `linprov notify` tray agent. Headless (no session bus / tray needed).
# The subscriber runs as root since the socket is 0600 root by default.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

FAILED=0
SOCK=/run/linprov/control.sock
SUBOUT=/tmp/linprov-smoke/sub.out
LOG=/tmp/linprov-smoke/daemon.log

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe
start_http_server /tmp/linprov-smoke

sudo bash -c "echo '' > /tmp/linprov-smoke/allow"
start_daemon enforce /tmp/linprov-smoke/allow "$LOG" || exit 1
fetch probe

echo "=== subscribe over the control socket, then trigger a block ==="
sudo rm -f "$SUBOUT"
# Subscribe and dump the stream to $SUBOUT for a few seconds.
# Subscriber: read the stream to $SUBOUT for a FIXED wall-clock window,
# then exit on its own. A wall-clock deadline (not an idle timeout) is
# essential — the daemon broadcasts every block system-wide, so on a busy
# box the stream may never go idle, and an idle-timeout subscriber would
# loop forever (and a bare `wait` would hang the whole suite).
sudo python3 - "$SOCK" "$SUBOUT" <<'PY' &
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(b"subscribe\n")
s.settimeout(0.5)
deadline = time.time() + 5
with open(sys.argv[2], "w") as f:
    while time.time() < deadline:
        try:
            d = s.recv(4096)
            if not d:
                break
            f.write(d.decode("utf-8", "replace"))
            f.flush()
        except socket.timeout:
            continue
PY
SUBPID=$!
sleep 1
/tmp/probe >/dev/null 2>&1   # marked + not allowlisted → blocked
wait "$SUBPID" 2>/dev/null   # subscriber self-exits at its 5s deadline
sudo pkill -9 -f 'control.sock' 2>/dev/null  # belt-and-suspenders

echo "--- subscriber received: ---"; sudo cat "$SUBOUT" 2>/dev/null
# Match the PROBE's block specifically (the stream may carry other blocks):
# wire form is BLOCK<TAB>token<TAB>kind<TAB>target<TAB>creator.
BLK_TOKEN=$(sudo awk -F'\t' '$1=="BLOCK" && $4=="/tmp/probe"{print $2; exit}' "$SUBOUT" 2>/dev/null)
LOG_TOKEN=$(grep 'BLOCKED-EXEC target=/tmp/probe' "$LOG" | grep -oE '\[allow: [0-9a-f]+\]' | grep -oE '[0-9a-f]{8}' | tail -1)
if [ -n "$BLK_TOKEN" ]; then
    echo "  OK   /tmp/probe BLOCK event streamed (token $BLK_TOKEN)"
else
    echo "  FAIL no /tmp/probe BLOCK event received over the subscribe stream"; FAILED=1
fi
if [ -n "$LOG_TOKEN" ] && [ "$BLK_TOKEN" = "$LOG_TOKEN" ]; then
    echo "  OK   stream token matches the [allow: $LOG_TOKEN] log line"
else
    echo "  FAIL token mismatch (stream=$BLK_TOKEN log=$LOG_TOKEN)"; FAILED=1
fi

cleanup_all
exit "$FAILED"

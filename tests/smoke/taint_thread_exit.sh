#!/bin/bash
# Regression for HIGH-1: a non-leader thread exiting must NOT clear a live
# process's network taint.
#
# `sched_process_exit` fires in do_exit() for EVERY thread, but the taint maps
# (NET_PIDS et al.) are keyed on the TGID. The buggy version reaped the TGID on
# any thread's exit, so the first worker thread to finish un-tainted the whole
# process — a file it wrote afterward was never marked (an unprivileged
# tracking bypass: connect, exit a throwaway thread, then drop the payload).
# The fix only reaps on thread-group-leader exit (tid == tgid).
#
# This test drives a multithreaded Python process: download (→ network-touched),
# spin up and JOIN a throwaway worker thread (whose exit triggered the bug),
# then write a file. The written file MUST be marked. Single-threaded curl can't
# exercise this, hence the bespoke writer.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

# The "marked ..." line is logged at DEBUG (INFO is reserved for execs).
export LINPROV_LOG_LEVEL=debug

cleanup_all
SMOKE=/tmp/linprov-smoke
OUT=/tmp/linprov-thread-out
rm -f "$OUT"
mkdir -p "$SMOKE"
cp -f /bin/true "$SMOKE/payload"
start_http_server "$SMOKE"

start_daemon observe - "$SMOKE/daemon-thread.log" || exit 1

# Multithreaded writer: connect (taint the TGID), exit a worker thread (the
# event that wrongly cleared the taint pre-fix), then write the output file.
prog=$(mktemp /tmp/linprov-thread-XXXXXX.py)
cat > "$prog" <<'PY'
import os, sys, threading, time, urllib.request
url, out = sys.argv[1], sys.argv[2]
data = urllib.request.urlopen(url, timeout=10).read()   # → network-touched (NET_PIDS[tgid])
t = threading.Thread(target=lambda: None)
t.start()
t.join()                                                # non-leader thread exits
time.sleep(0.3)                                         # ensure its do_exit() fired
with open(out, "wb") as f:                              # write AFTER the thread exit
    f.write(data)
    f.flush()
    os.fsync(f.fileno())
PY
python3 "$prog" "http://127.0.0.1:$LINPROV_HTTP_PORT/payload" "$OUT"
rm -f "$prog"
sleep 1

rc=0
echo "=== xattr on $OUT (record bytes expected; empty == taint was wrongly cleared) ==="
if sudo getfattr --only-values -n security.bpf.linprov.origin "$OUT" 2>/dev/null \
    | od -An -tx1 -N 16 | grep -qE '[0-9a-f]'; then
    sudo getfattr --only-values -n security.bpf.linprov.origin "$OUT" 2>/dev/null \
        | od -An -tx1 -N 16 | head -1
    echo "  OK   $OUT marked despite the worker-thread exit"
else
    echo "  FAIL $OUT is unmarked — a non-leader thread exit cleared the process taint"
    rc=1
fi

echo "=== daemon log (expect 'marked $OUT') ==="
if grep -qE "marked $OUT\b" "$SMOKE/daemon-thread.log"; then
    grep -E "marked $OUT\b" "$SMOKE/daemon-thread.log" | head -1
    echo "  OK   mark logged"
else
    echo "  FAIL no mark logged for $OUT"
    rc=1
fi

cleanup_all
exit "$rc"

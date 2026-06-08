#!/bin/bash
# Archive-aware provenance (read-taint propagation).
#
# A process that READS a marked inode is tainted; files it later WRITES
# inherit the source's OriginRecord (with their own landing path). So:
#   * `tar xf` of a *downloaded* (marked) archive marks the extracted files,
#     and the derived mark carries the inherited creator identity (comm);
#   * `tar xf` of a never-downloaded (unmarked) archive marks nothing;
#   * the derived on-disk xattr drives `bprm_check_security` in enforce mode
#     exactly like a native mark.
#
# Propagation is same-boot: it reads INODE_MARKS, which is per-daemon-session.
# We therefore extract ONCE while the downloading daemon is live; the derived
# xattr persists on disk and is what the later enforce daemons see.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

# The "marked (derived) ..." line is logged at DEBUG (INFO is reserved for
# execs), and the observe phase asserts on it.
export LINPROV_LOG_LEVEL=debug

cleanup_all
SMOKE=/tmp/linprov-smoke
EXTRACT=$SMOKE/extract
EXTRACT_NEG=$SMOKE/extract-neg
rm -rf "$EXTRACT" "$EXTRACT_NEG" "$SMOKE/payload" "$SMOKE/payload.tar"
mkdir -p "$SMOKE" "$EXTRACT" "$EXTRACT_NEG" "$SMOKE/payload"

# Build the archive locally with `tar` (no network) → the archive file itself
# is unmarked. The http server hands out this same file; the *downloaded copy*
# is what gets marked (curl is network-touched).
cp -f /bin/true "$SMOKE/payload/probe"
tar cf "$SMOKE/payload.tar" -C "$SMOKE/payload" probe

start_http_server "$SMOKE"

# ---- Observe phase: download (mark) the archive, then extract. ----
start_daemon observe - "$SMOKE/daemon-observe.log" || exit 1

fetch payload.tar                         # curl writes /tmp/payload.tar → marked
sleep 2                                   # let userspace back-fill INODE_MARKS
tar xf /tmp/payload.tar -C "$EXTRACT"     # tar reads marked archive → inherits
sleep 1

echo "=== derived xattr on $EXTRACT/probe (expect record bytes) ==="
sudo getfattr --only-values -n security.bpf.linprov.origin "$EXTRACT/probe" 2>/dev/null \
    | od -An -tx1 -N 48 | head -3

echo "=== derived mark log line (expect 'marked (derived)' for the probe) ==="
grep -E 'marked \(derived\).*'"$EXTRACT"'/probe' "$SMOKE/daemon-observe.log" | head -3
echo "    (creator_path above is best-effort: curl may exit before the daemon"
echo "     reads /proc/\$pid/exe; creator comm/uid/ts always propagate.)"

# Negative: extract the never-downloaded local archive → nothing marked.
tar xf "$SMOKE/payload.tar" -C "$EXTRACT_NEG"
sleep 1
echo "=== negative: $EXTRACT_NEG/probe from un-downloaded archive (expect NO xattr) ==="
if sudo getfattr --only-values -n security.bpf.linprov.origin "$EXTRACT_NEG/probe" >/dev/null 2>&1; then
    echo "  UNEXPECTED: $EXTRACT_NEG/probe is marked"
else
    echo "  OK: $EXTRACT_NEG/probe is unmarked"
fi

# ---- Enforce phase: the derived xattr drives bprm like a native mark. ----
# No re-extraction: the archive's INODE_MARKS entry is gone after the restart,
# but $EXTRACT/probe keeps its on-disk derived xattr.

# E1: the inherited creator_comm (curl) matches → PASS.
sudo bash -c 'echo "creator_comm=curl" > '"$SMOKE/allow"
start_daemon enforce "$SMOKE/allow" "$SMOKE/daemon-e1.log" || exit 1
echo "=== E1 creator_comm=curl (inherited from the archive) — expect PASS ==="
exec_check derived-probe "$EXTRACT/probe"

# E2: wrong inherited creator_comm → BLOCK (control).
sudo bash -c 'echo "creator_comm=wget" > '"$SMOKE/allow"
start_daemon enforce "$SMOKE/allow" "$SMOKE/daemon-e2.log" || exit 1
echo "=== E2 creator_comm=wget — expect BLOCK ==="
exec_check derived-probe "$EXTRACT/probe" || true

cleanup_all

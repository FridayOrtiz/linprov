#!/bin/bash
# Daemon loads in observe mode, a curl download gets marked.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe
start_http_server /tmp/linprov-smoke

start_daemon observe - /tmp/linprov-smoke/daemon.log || exit 1

fetch probe
sleep 1

echo "=== xattr (decoded prefix bytes) ==="
sudo getfattr --only-values -n security.bpf.linprov.origin /tmp/probe 2>/dev/null \
    | od -An -tx1 -N 48 | head -3

echo "=== daemon log ==="
grep -E 'marked /tmp/probe' /tmp/linprov-smoke/daemon.log | head -3

cleanup_all

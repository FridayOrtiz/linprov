#!/bin/bash
# PATH_MAX support + nested landing-folder matching (schema v4).
#
# Exercises paths that exceed the old 256-byte ceiling, and the
# ancestor-hash nesting: a file that lands deep is matched by a rule
# naming a shallow ancestor of its landing folder.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe
start_http_server /tmp/linprov-smoke

# Build a landing dir whose path comfortably exceeds 256 bytes.
SEG=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # 36 chars
DEEP=/tmp/linprov-deep
for _ in $(seq 1 8); do DEEP="$DEEP/$SEG"; done
sudo rm -rf /tmp/linprov-deep
sudo mkdir -p "$DEEP"
echo "=== landing dir is ${#DEEP} bytes (> 256) ==="

# fetch_to <url-name> <dest>: download from the smoke server to an
# arbitrary path and make it executable.
fetch_to() {
    sudo rm -f "$2"
    sudo curl -fsS -o "$2" "http://127.0.0.1:$LINPROV_HTTP_PORT/$1"
    sudo chmod +x "$2"
}

# T1: target_folder at the full deep path — file marked and executed in
# place, rule names its (long) immediate folder. Expect PASS.
sudo bash -c "echo 'target_folder=$DEEP/;creator_comm=curl' > /tmp/linprov-smoke/allow"
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-deep1.log || exit 1
fetch_to probe "$DEEP/prog"
echo "=== T1 target_folder=<316B path> — expect PASS ==="
exec_check probe "$DEEP/prog"

# T2: nested landing. The file landed deep; the rule names a SHALLOW
# ancestor of that landing folder. Expect PASS (ancestor-hash match).
sudo bash -c "echo 'landing_folder=/tmp/linprov-deep/;creator_comm=curl' > /tmp/linprov-smoke/allow"
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-deep2.log || exit 1
fetch_to probe "$DEEP/prog"
echo "=== T2 landing_folder=/tmp/linprov-deep/ (shallow ancestor of deep landing) — expect PASS ==="
exec_check probe "$DEEP/prog"

# T3: nested landing negative — a folder that is NOT an ancestor of the
# landing path. Expect BLOCK.
sudo bash -c "echo 'landing_folder=/tmp/somewhere-else/;creator_comm=curl' > /tmp/linprov-smoke/allow"
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-deep3.log || exit 1
fetch_to probe "$DEEP/prog"
echo "=== T3 landing_folder=/tmp/somewhere-else/ (not an ancestor) — expect BLOCK ==="
exec_check probe "$DEEP/prog" || true

cleanup_all
sudo rm -rf /tmp/linprov-deep

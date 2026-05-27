#!/bin/bash
# AND-within-a-rule, OR-across-lines, and landing_* vs target_*.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe-a
start_http_server /tmp/linprov-smoke

UID_VAL=$(id -u)

# T1: AND inside a rule — comm matches, uid doesn't → BLOCK.
sudo bash -c 'echo "creator_comm=curl;creator_uid=99999" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-t1.log || exit 1
fetch probe-a
echo "=== T1 creator_comm=curl;creator_uid=99999 — expect BLOCK ==="
exec_check probe-a /tmp/probe-a || true

# T2: AND with matching values → PASS.
sudo bash -c "echo 'creator_comm=curl;creator_uid=$UID_VAL' > /tmp/linprov-smoke/allow"
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-t2.log || exit 1
fetch probe-a
echo "=== T2 creator_comm=curl;creator_uid=$UID_VAL — expect PASS ==="
exec_check probe-a /tmp/probe-a

# T3: two-line OR — line1 (wrong uid) fails, line2 (execution_uid) passes.
sudo bash -c "cat > /tmp/linprov-smoke/allow <<EOF
creator_comm=curl;creator_uid=99999
execution_uid=$UID_VAL
EOF"
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-t3.log || exit 1
fetch probe-a
echo "=== T3 line1 fails / line2 passes — expect PASS ==="
exec_check probe-a /tmp/probe-a

# T4: landing_folder vs target_folder. Download to /tmp/, move into
# /opt/installed/, exec. landing_folder=/tmp/ should match;
# landing_folder=/var/cache/ should not.
sudo mkdir -p /opt/installed
sudo bash -c 'echo "landing_folder=/tmp/;creator_comm=curl" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-t4a.log || exit 1
fetch probe-a
sudo rm -f /opt/installed/probe-a
sudo mv /tmp/probe-a /opt/installed/probe-a
echo "=== T4a landing_folder=/tmp/ (file moved to /opt/installed/) — expect PASS ==="
exec_check probe-a /opt/installed/probe-a

sudo bash -c 'echo "landing_folder=/var/cache/;creator_comm=curl" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-t4b.log || exit 1
sudo rm -f /opt/installed/probe-a
fetch probe-a
sudo mv /tmp/probe-a /opt/installed/probe-a
echo "=== T4b landing_folder=/var/cache/ — expect BLOCK ==="
exec_check probe-a /opt/installed/probe-a || true

# T5: target_folder matches the exec-time location.
sudo bash -c 'echo "target_folder=/opt/installed/;creator_comm=curl" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon-t5.log || exit 1
sudo rm -f /opt/installed/probe-a
fetch probe-a
sudo mv /tmp/probe-a /opt/installed/probe-a
echo "=== T5 target_folder=/opt/installed/ — expect PASS ==="
exec_check probe-a /opt/installed/probe-a

cleanup_all

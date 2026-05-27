#!/bin/bash
# Soak with default --soak (creator_process) and full CSV. Output is
# enforce-able.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe-a
cp -f /bin/true /tmp/linprov-smoke/probe-b
start_http_server /tmp/linprov-smoke

sudo rm -f /tmp/linprov-smoke/soak-default /tmp/linprov-smoke/soak-full

# Default soak — should emit one creator_process rule per distinct
# creator, deduped.
start_daemon soak /tmp/linprov-smoke/soak-default /tmp/linprov-smoke/daemon-default.log || exit 1
fetch_all probe-a probe-b
/tmp/probe-a > /dev/null
/tmp/probe-b > /dev/null
# Re-exec probe-a — dedup should swallow it.
/tmp/probe-a > /dev/null
sleep 1
echo "=== default soak output ==="
sudo cat /tmp/linprov-smoke/soak-default

# Full soak — every dim joined into a single rule per event.
start_daemon soak /tmp/linprov-smoke/soak-full /tmp/linprov-smoke/daemon-full.log \
    --soak creator_process,creator_comm,creator_uid,target_filename,target_folder \
    || exit 1
fetch_all probe-a probe-b
/tmp/probe-a > /dev/null
/tmp/probe-b > /dev/null
sleep 1
echo
echo "=== full soak output ==="
sudo cat /tmp/linprov-smoke/soak-full

# Feed full soak output back into enforce — same files should pass.
# We've torn down the http server in cleanup_all above; spin it back up
# so fetch_all has something to talk to.
cleanup_all
start_http_server /tmp/linprov-smoke
start_daemon enforce /tmp/linprov-smoke/soak-full /tmp/linprov-smoke/daemon-enforce.log || exit 1
fetch_all probe-a probe-b
echo
echo "=== enforce against soak output — expect PASS for both ==="
exec_check probe-a /tmp/probe-a
exec_check probe-b /tmp/probe-b

cleanup_all

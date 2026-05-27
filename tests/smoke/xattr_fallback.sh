#!/bin/bash
# Restart the daemon (which wipes inode_storage), then exec a
# previously-marked file. The persisted xattr should still drive
# enforcement.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

cleanup_all
mkdir -p /tmp/linprov-smoke
cp -f /bin/true /tmp/linprov-smoke/probe-a
cp -f /bin/true /tmp/linprov-smoke/probe-b
start_http_server /tmp/linprov-smoke

sudo bash -c "echo 'creator_comm=curl' > /tmp/linprov-smoke/allow"

echo "=== first daemon: mark files ==="
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon1.log || exit 1
fetch_all probe-a probe-b

echo "=== restart daemon — inode_storage wipes, xattr remains ==="
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon2.log || exit 1
echo "=== exec probe-a (allowed via xattr-stored origin) ==="
exec_check probe-a /tmp/probe-a
echo "=== exec probe-b (allowed via xattr-stored origin) ==="
exec_check probe-b /tmp/probe-b

# Narrow to a non-matching rule — both should now block, proving the
# xattr is in fact the source of the now-different decision.
sudo bash -c "echo 'creator_uid=99999' > /tmp/linprov-smoke/allow"
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon3.log || exit 1
echo "=== narrow allowlist; probe-a should now BLOCK from xattr ==="
exec_check probe-a /tmp/probe-a || true

cleanup_all

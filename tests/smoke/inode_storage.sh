#!/bin/bash
# Strip the xattr after marking — enforce still works because
# inode_storage holds the mark.
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

start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log || exit 1
fetch_all probe-a probe-b

echo "=== strip xattrs — only inode_storage holds the mark now ==="
sudo setfattr -x security.bpf.linprov.origin /tmp/probe-a
sudo setfattr -x security.bpf.linprov.origin /tmp/probe-b

# probe-a permitted via creator_comm rule, probe-b blocked because we
# narrow the allowlist to a creator_uid that doesn't match.
echo "=== exec probe-a (creator_comm matches; inode_storage path) ==="
exec_check probe-a /tmp/probe-a

# Narrow the allowlist to a UID that won't match, then re-download
# probe-b so the new daemon marks it (inode_storage gets a fresh
# creator_uid=1000 entry); strip the xattr again so only inode_storage
# carries the mark. The rule wants UID 99999 → expect BLOCK.
sudo bash -c "echo 'creator_uid=99999' > /tmp/linprov-smoke/allow"
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log || exit 1
fetch probe-b
sudo setfattr -x security.bpf.linprov.origin /tmp/probe-b
echo "=== exec probe-b (mark via inode_storage, wrong-uid rule → BLOCK) ==="
exec_check probe-b /tmp/probe-b || true

cleanup_all

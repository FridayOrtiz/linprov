#!/bin/bash
# Entry point: run every smoke test in sequence, fail on first error.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

fail=0
for script in basic.sh inode_storage.sh xattr_fallback.sh and_or.sh deep_paths.sh propagate.sh scripts.sh hot_reload.sh overflow.sh soak.sh; do
    echo
    echo "######## $script ########"
    if ! "$here/$script"; then
        echo "FAILED: $script" >&2
        fail=1
    fi
    # Give the kernel and the python http.server a beat to release
    # state between scripts (lingering daemon SIGKILL cleanup, port
    # 8000 TIME_WAIT, etc.).
    sleep 2
done
exit "$fail"

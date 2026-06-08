#!/bin/bash
# Script support: a marked script is enforced even when run via an
# interpreter (`bash foo.sh` / `. foo.sh`), not just as a shebang
# (`./foo.sh`). And an allowlist rule keyed on the script (target_filename
# / target_folder) permits BOTH invocation styles identically.
set -u
here=$(dirname "$(realpath "$0")")
. "$here/common.sh"
smoke_preflight

FAILED=0

# run_case <label> <pass|block> <cmd...> — run cmd, compare outcome.
run_case() {
    local label=$1 expect=$2
    shift 2
    local got
    if "$@" >/dev/null 2>&1; then got=pass; else got=block; fi
    if [ "$got" = "$expect" ]; then
        echo "  OK   $label ($got)"
    else
        echo "  FAIL $label (got $got, expected $expect)"
        FAILED=1
    fi
}

cleanup_all
mkdir -p /tmp/linprov-smoke
cat > /tmp/linprov-smoke/hello.sh <<'SH'
#!/bin/bash
echo "HELLO-FROM-SCRIPT"
SH
chmod +x /tmp/linprov-smoke/hello.sh
# A script that reads its own (separately-marked) data file, for the
# "allowlisted script may do file I/O" case below.
cat > /tmp/linprov-smoke/runner.py <<'PY'
print("DATA:" + open("/tmp/data.txt").read().strip())
PY
echo "secret-payload" > /tmp/linprov-smoke/data.txt
start_http_server /tmp/linprov-smoke

echo "=== ENFORCE, empty allowlist — every invocation blocks ==="
sudo bash -c 'echo "" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log || exit 1
fetch hello.sh
run_case "bash /tmp/hello.sh"            block bash /tmp/hello.sh
run_case ". /tmp/hello.sh (source)"      block bash -c '. /tmp/hello.sh'
run_case "/tmp/hello.sh (shebang)"       block /tmp/hello.sh
sleep 1
echo "--- expect BLOCKED-SCRIPT (interpreter) + BLOCKED-EXEC (shebang) in log:"
if grep -q 'BLOCKED-SCRIPT' /tmp/linprov-smoke/daemon.log; then
    echo "  OK   BLOCKED-SCRIPT logged"
else
    echo "  FAIL no BLOCKED-SCRIPT line"; FAILED=1
fi
grep -qE 'BLOCKED-(SCRIPT|EXEC)' /tmp/linprov-smoke/daemon.log \
    && echo "  OK   shebang/interpreter blocks logged" \
    || { echo "  FAIL no block lines"; FAILED=1; }

echo "=== ENFORCE, target_filename — permits interpreter AND shebang alike ==="
sudo bash -c 'echo "target_filename=/tmp/hello.sh" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log || exit 1
fetch hello.sh
run_case "bash /tmp/hello.sh"      pass bash /tmp/hello.sh
run_case "/tmp/hello.sh (shebang)" pass /tmp/hello.sh

echo "=== ENFORCE, target_folder=/tmp/ — same consistency ==="
sudo bash -c 'echo "target_folder=/tmp/" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log || exit 1
fetch hello.sh
run_case "bash /tmp/hello.sh"      pass bash /tmp/hello.sh
run_case "/tmp/hello.sh (shebang)" pass /tmp/hello.sh

echo "=== ENFORCE, empty interpreters — script enforcement disabled ==="
# With no interpreters configured the read branch never blocks; the
# interpreter-invoked script runs even under an empty allowlist (the
# shebang form is still blocked by the execve hook).
sudo bash -c 'echo "" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log --interpreters '' || exit 1
fetch hello.sh
run_case "bash /tmp/hello.sh (enforcement off)" pass bash /tmp/hello.sh

echo "=== ENFORCE, allowlisted script may read its own marked data ==="
# Both runner.py and data.txt are marked (downloaded), but only the
# *script* is allowlisted. Once the interpreter is cleared to run the
# approved script, its subsequent marked reads (the data file) must pass —
# just like an allowlisted ELF reads marked files freely. Without per-PID
# approval the open() of /tmp/data.txt would be blocked and python exits 1.
sudo bash -c 'echo "target_filename=/tmp/runner.py" > /tmp/linprov-smoke/allow'
start_daemon enforce /tmp/linprov-smoke/allow /tmp/linprov-smoke/daemon.log || exit 1
fetch runner.py
fetch data.txt
run_case "python /tmp/runner.py reads marked /tmp/data.txt" pass python3 /tmp/runner.py

echo "=== OBSERVE — runs, logs PROVENANCE-SCRIPT ==="
LINPROV_LOG_LEVEL=info start_daemon observe - /tmp/linprov-smoke/daemon.log || exit 1
fetch hello.sh
run_case "bash /tmp/hello.sh (observe)" pass bash /tmp/hello.sh
sleep 1
grep -q 'PROVENANCE-SCRIPT' /tmp/linprov-smoke/daemon.log \
    && echo "  OK   PROVENANCE-SCRIPT logged" \
    || { echo "  FAIL no PROVENANCE-SCRIPT line"; FAILED=1; }

cleanup_all
exit "$FAILED"

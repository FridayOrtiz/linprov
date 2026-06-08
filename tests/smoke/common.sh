# Shared bash helpers for the smoke suite. Source from each script.
#
# Conventions:
#   - LINPROV_BIN points to the daemon binary (default: target/debug/linprov).
#   - All scripts run from the repo root so relative paths work.
#   - We pre-flight that BPF LSM is active before starting the daemon.

set -u

: "${LINPROV_BIN:=./target/debug/linprov}"
: "${LINPROV_HTTP_PORT:=8000}"

require_root() {
    if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
        echo "These tests need root (or passwordless sudo)." >&2
        exit 2
    fi
}

require_bpf_lsm() {
    if [ ! -f /sys/kernel/security/lsm ]; then
        echo "BPF LSM not available — /sys/kernel/security/lsm missing." >&2
        exit 2
    fi
    if ! grep -q '\bbpf\b' /sys/kernel/security/lsm; then
        echo "BPF LSM not in active lsm list ($(cat /sys/kernel/security/lsm))." >&2
        echo "Add 'bpf' to the lsm= boot param and reboot." >&2
        exit 2
    fi
}

require_binary() {
    if [ ! -x "$LINPROV_BIN" ]; then
        echo "linprov binary not found at $LINPROV_BIN. Run 'cargo build' first." >&2
        exit 2
    fi
}

# Kill just the running linprov daemon. start_daemon calls this to make
# room for the new daemon; it intentionally does NOT touch the python
# http server we spawned at the start of each script.
#
# We resolve PIDs via /proc/*/comm rather than `pkill -f` because the
# latter has historically had self-match issues here (the pkill command
# line contains its own pattern argument).
cleanup_daemons() {
    local pids
    pids=$(pgrep -x linprov || true)
    if [ -n "$pids" ]; then
        # shellcheck disable=SC2086
        sudo kill -9 $pids 2>/dev/null || true
    fi
    sleep 1
}

# Kill everything (daemon + http server). Tests call this at start and
# end as a hygiene measure.
cleanup_all() {
    cleanup_daemons
    local pids
    pids=$(pgrep -f "python3 -m http.server $LINPROV_HTTP_PORT" || true)
    if [ -n "$pids" ]; then
        # shellcheck disable=SC2086
        kill $pids 2>/dev/null || true
    fi
    sleep 1
}

# Start a python http.server serving from $1 on $LINPROV_HTTP_PORT.
start_http_server() {
    local serve_dir=$1
    (cd "$serve_dir" && setsid python3 -m http.server "$LINPROV_HTTP_PORT" \
        > /tmp/linprov-test-server.log 2>&1 < /dev/null &)
    sleep 1
}

# Start the daemon in the given mode with the given allowlist path; log
# goes to $logfile. Echoes "ok" or "fail" and the log tail on failure.
#   start_daemon <mode> <allowlist|-> <logfile> [extra args...]
start_daemon() {
    local mode=$1 allowlist=$2 logfile=$3
    shift 3
    cleanup_daemons
    rm -f "$logfile"

    # `run` subcommand. Empty --config keeps us off /etc/linprov/config.toml
    # — the smoke suite is purely CLI-driven. Log level defaults to info;
    # tests that assert on the (DEBUG-level) "marked ..." lines set
    # LINPROV_LOG_LEVEL=debug.
    local args=(run --config /dev/null --mode "$mode" --log-level "${LINPROV_LOG_LEVEL:-info}")
    if [ "$allowlist" != "-" ]; then
        args+=(--allowlist "$allowlist")
    fi
    args+=("$@")

    # The smoke server runs on 127.0.0.1, which the daemon ignores by
    # default. Flip mark-localhost on so the test fetches actually
    # produce marks.
    setsid sudo LINPROV_MARK_LOCALHOST=1 "$LINPROV_BIN" "${args[@]}" \
        > "$logfile" 2>&1 < /dev/null &

    # Poll for readiness rather than a fixed sleep: BPF verification time
    # varies with the program and machine load, so a flat sleep races on a
    # busy host (back-to-back tests, larger programs). Wait up to ~10s.
    local i
    for i in $(seq 1 100); do
        if grep -q 'linprov running' "$logfile" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    if ! grep -q 'linprov running' "$logfile"; then
        echo "daemon failed to start"
        tail -20 "$logfile" >&2
        return 1
    fi
}

# Download $1 from the http.server to /tmp/<basename>. Sets the
# executable bit so an immediate exec works.
fetch() {
    local name=$1
    rm -f "/tmp/$name"
    curl -fsS -o "/tmp/$name" "http://127.0.0.1:$LINPROV_HTTP_PORT/$name"
    chmod +x "/tmp/$name"
}

# Like `fetch`, but downloads multiple names with the same server.
fetch_all() {
    for n in "$@"; do
        fetch "$n"
    done
}

# Run a binary and echo PASS/BLOCK. Returns the binary's exit status.
exec_check() {
    local label=$1 binary=$2
    if "$binary" 2>/dev/null; then
        echo "  PASS $label"
        return 0
    else
        local rc=$?
        echo "  BLOCK $label exit=$rc"
        return "$rc"
    fi
}

# Refuse to run if a production linprov daemon is already up. The suite
# kills ALL linprov processes (`cleanup_daemons`) and the BPF LSM hooks
# are system-global, so a daemon running alongside would be (a) disrupted
# — killed and, if systemd-managed, immediately restarted mid-test — and
# (b) recording the suite's own download/exec activity into its real
# allowlist (a soak daemon pollutes `/etc/linprov/list.allow`). The smoke
# daemons themselves are isolated (`--config /dev/null`, a `/tmp`
# allowlist); this guards the *other* daemon.
require_no_production_daemon() {
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active --quiet linprov.service 2>/dev/null; then
        echo "linprov.service is active. Stop it before running the smoke suite:" >&2
        echo "    sudo systemctl stop linprov.service" >&2
        echo "(the suite kills all linprov processes and shares the global BPF LSM" >&2
        echo " hooks; a running soak daemon would record test activity into your" >&2
        echo " real allowlist.)" >&2
        exit 2
    fi
    # Also catch a hand-started daemon that isn't using the throwaway
    # `--config /dev/null` the suite runs with.
    local prod
    prod=$(pgrep -af 'linprov run' 2>/dev/null \
        | grep -v -- '--config /dev/null' | grep -v 'pgrep' || true)
    if [ -n "$prod" ]; then
        echo "A linprov daemon is already running (not the smoke throwaway config):" >&2
        echo "    $prod" >&2
        echo "Stop it before running the smoke suite." >&2
        exit 2
    fi
}

# Pre-flight before any test.
smoke_preflight() {
    require_root
    require_bpf_lsm
    require_binary
    require_no_production_daemon
}

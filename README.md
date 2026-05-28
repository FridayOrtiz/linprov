# linprov

eBPF-based mark-of-the-web for Linux. Every file written by a process that
touched the network gets tagged with a provenance xattr; every `execve` of
a tagged file is logged, and — optionally — blocked unless the path is on
an explicit allowlist.

## How it works

Three sleepable BPF LSM hooks plus one cleanup tracepoint:

| Hook | What it does |
|---|---|
| `socket_connect` | When a PID `connect()`s to a non-loopback `AF_INET`/`AF_INET6` address, mark the PID as network-touched in an LRU hash map. Loopback connects (`127.0.0.0/8`, `::1`) are skipped by default — pass `--mark-localhost` or `LINPROV_MARK_LOCALHOST=1` to include them (e.g. for the smoke tests, which use a local HTTP server). |
| `file_open` | If the opener is network-touched and the file is opened for write, write the OriginRecord into a `BPF_MAP_TYPE_INODE_STORAGE` map keyed on the file's inode, and emit a ringbuf event with the path. |
| `bprm_check_security` | On every exec, look the inode up in INODE_MARKS first; if absent, fall back to the `bpf_get_file_xattr` kfunc. If either source has the mark, emit a ringbuf event — and in enforce mode, return `-EPERM` for paths not on the allowlist. |
| `sched_process_exit` (tracepoint) | Reap the network-touched PID entry on task teardown. |

Userspace consumes the ringbuf, applies the `security.bpf.linprov.origin`
xattr (the kernel restricts `bpf_set_dentry_xattr` to LSM hooks that
natively take a trusted dentry, which `file_open` isn't), and — in
enforce mode — seeds an in-kernel hash map of permitted paths.

The two mark sources play different roles:

- **INODE_MARKS** is the same-boot fast path. Synchronous in `file_open`,
  so by the time the very next `execve` runs, the mark is already
  visible to `bprm_check_security`. Closes the race window where a freshly
  downloaded binary could exec before userspace landed the xattr.
- **The xattr** is the durability layer. Survives daemon restart,
  reboots, and inode cache eviction. Written off-band by userspace; read
  in-kernel as fallback.

Either source produces the same OriginRecord — enforcement / logging
doesn't care which fired.

## Requirements

- Linux **6.5+** kernel with BPF LSM enabled (`CONFIG_BPF_LSM=y`, `bpf` in
  the active `lsm=` boot parameter). Confirm with:
  ```
  cat /sys/kernel/security/lsm  # must contain `bpf`
  ```
  On Pop!_OS / Ubuntu with systemd-boot:
  ```
  sudo kernelstub -a "lsm=$(cat /sys/kernel/security/lsm),bpf"
  # then reboot
  ```
- vmlinux BTF (`/sys/kernel/btf/vmlinux`) — needed for LSM hook resolution.
- Rust nightly (pinned via `rust-toolchain.toml`).
- The userspace daemon runs as **root** (BPF program load + LSM attach +
  `security.bpf.*` xattr writes all need it).

## Install

```
cargo install bpf-linker
cargo install linprov
sudo $(which linprov) setup
```

`cargo install` drops the binary in `~/.cargo/bin/`, which isn't on
root's `secure_path` — that's why the first invocation needs the
absolute path. `linprov setup` immediately copies itself to
`/usr/local/bin/linprov`, so every later `sudo linprov ...` (and
`linprov upgrade`) resolves without help. Uses an aya fork published
as `aya-friday-*` on crates.io — pulled in automatically as a regular
dependency.

## Build from source

```
cargo build --release
```

## Tests

```
# Unit tests + doctests (no kernel needed):
cargo test --workspace

# Smoke suite (needs root + BPF LSM kernel; see tests/README.md):
cargo build
sudo ./tests/smoke/run-all.sh
```

## Run

`linprov` is structured as three subcommands. The recommended
end-to-end flow is **setup → soak → review → enforce**.

### 1. `linprov setup`

Feature-checks the kernel (≥ 6.5, `bpf` in active `lsm=`, `vmlinux`
BTF), copies the running binary to `/usr/local/bin/linprov`, writes a
commented `/etc/linprov/config.toml`, an empty allowlist at
`/etc/linprov/list.allow`, and a systemd unit (writes only — doesn't
enable). The config it writes starts in `mode = "observe"`; don't
enable the unit yet.

```
sudo $(which linprov) setup    # first time only; sudo can't find ~/.cargo/bin
```

After this, the binary's at `/usr/local/bin/linprov` (on root's
`secure_path`), so `sudo linprov ...` works from anywhere.

### 2. Soak interactively to build an allowlist

Run the daemon in the foreground while you use your machine
normally. Every marked `execve` appends one rule to the allowlist
file. `^C` when you've covered enough — the rules persist on disk.

```
sudo linprov run --mode soak
journalctl is not involved here; logs stream to your terminal.
```

The `--mode soak` flag overrides the config's `mode = "observe"`;
the rest of the config (allowlist path, soak dims, etc.) is still
honored. Watch the file grow:

```
tail -f /etc/linprov/list.allow
```

### 3. Review the allowlist

Trim anything you didn't actually want permitted:

```
cat /etc/linprov/list.allow
$EDITOR /etc/linprov/list.allow
```

### 4. Flip to enforce and start the unit

Edit `/etc/linprov/config.toml` and change `mode = "observe"` to
`mode = "enforce"`. Then enable the systemd unit:

```
sudo systemctl daemon-reload
sudo systemctl enable --now linprov.service
journalctl -u linprov.service -f
```

A marked execve that doesn't match any rule now gets blocked with
`-EPERM` from `security_bprm_check` — the shell sees
`Operation not permitted` and `$?` is `126`.

### `linprov upgrade`

After `cargo install --force linprov` drops a new binary in
`~/.cargo/bin/`:

```
sudo linprov upgrade
```

The running binary is `/usr/local/bin/linprov` (an *old* version);
`upgrade` resolves your `~/.cargo/bin/linprov` automatically — via
`$SUDO_USER` / `$DOAS_USER` / `$PKEXEC_UID` / `logname` / euid's home,
falling back to a unique-match scan of `/etc/passwd` — then copies it
over `/usr/local/bin/linprov` and runs `systemctl daemon-reload` +
`systemctl restart linprov.service`. If autodetect fails (multi-user
host, weird shell setup), point it explicitly: `sudo linprov upgrade
--source /path/to/new/linprov`.

If the source already matches the install path byte-for-byte,
`upgrade` reports it and skips the restart instead of bouncing the
daemon for nothing.

### `linprov run` reference

Reads `/etc/linprov/config.toml` by default; CLI flags + env vars
override. The systemd unit calls `linprov run --config
/etc/linprov/config.toml`. Three modes:

- **observe** (default): mark files, log marked execs, never block.
- **soak**: like observe plus appending one allowlist rule per
  PROVENANCE-EXEC. `--soak creator_process,creator_uid,…` (also
  settable as `soak = [...]` in the config) controls which dims each
  emitted rule AND-joins.
- **enforce**: block any marked execve whose origin doesn't match a
  rule.

By default logs go to stderr (journald captures them under
systemd). Set `log_file = "/path/to/file"` in the config (or
`--log-file`) to append-log to a file instead — handy for non-systemd
setups.

Sample log lines for observe / enforce:

```
PROVENANCE-EXEC target=/usr/local/bin/foo landing=/tmp/foo pid=12345 \
  comm=zsh origin={v:3,…,comm:curl,path:/usr/bin/curl}
BLOCKED-EXEC target=/tmp/sketchy landing=/tmp/sketchy pid=12346 comm=zsh \
  origin={v:3,…,comm:curl,path:/usr/bin/curl} (LSM verdict -1)
```

## Allowlist format

One rule per line. `#` starts a comment; blank lines are ignored. Each
line is one rule whose `<dim>=<value>;<dim>=<value>` conditions **AND**
together. Multiple lines **OR**: a marked execve is permitted if any
single rule's conditions all match.

```
# uid 1000 downloading with curl is fine, anywhere
creator_uid=1000;creator_comm=curl

# uid 1000 may exec firefox-dropped binaries that ended up in ~/.local/bin
execution_uid=1000;creator_comm=firefox;target_folder=/home/user/.local/bin
```

| dim | example | matches if … |
|---|---|---|
| `target_filename` | `/usr/bin/foo` | the executed binary's path equals this |
| `target_folder` | `/opt/installed/` | the executed binary lives under this prefix (any depth) |
| `landing_filename` | `/tmp/foo` | the file's *download* path (where it was first written) equals this |
| `landing_folder` | `/tmp/` | the file's *download* directory matches at any depth |
| `creator_process` | `/usr/bin/curl` | the full `exe` path of the writer matches |
| `creator_comm` | `curl` | the 16-byte `comm` of the writer matches |
| `creator_uid` | `1000` | the writer's UID matches |
| `execution_uid` | `0` | the UID running the `execve` matches |

`target_*` reflects the file's location at execve time; `landing_*` is
where it was first written. They diverge when the file is moved between
download and execve — e.g. `curl -o /tmp/foo http://…; mv /tmp/foo
~/.local/bin/foo; ~/.local/bin/foo` has `landing_filename=/tmp/foo` and
`target_filename=~/.local/bin/foo`.

Folder rules must end in `/` (userspace normalizes). All path-shaped
values are bounded to 64 bytes by the BPF FNV walk; longer rules are
rejected at parse time.

Up to 32 rules per allowlist (BPF verifier budget — bump
`MAX_RULES` and rebuild for more).

`creator_process` is populated by userspace via `readlink /proc/$pid/exe`
when handling the file-open event. If the creator process exits before
userspace lands the augmented xattr, rules requiring `creator_process`
won't match for that file — use `creator_comm` (always populated by BPF)
as the fallback dim.

## Inspecting the xattr by hand

```
getfattr -d -m '.*' /path/to/file
# security.bpf.linprov.origin=0sAgAAAA...
```

The value is the binary `OriginRecord` (v3 layout):

```
version u32 | pid u32 | ts_boot_ns u64 | comm[16] |
creator_uid u32 | _pad u32 | creator_path[256] | landing_filename[256]
```

The daemon's log lines already format it. Earlier-version xattrs from
prior linprov builds are ignored (treated as unmarked).

## Roadmap

See [`ROADMAP.md`](ROADMAP.md).

## Repository layout

```
linprov/         userspace daemon (clap, tokio, aya)
linprov-ebpf/    BPF programs (no_std, aya-ebpf, inline asm for kfuncs)
linprov-common/  types shared between the two
tests/smoke/     end-to-end tests against a real kernel
.github/         CI workflows
```

## License

Userspace crates: dual-licensed under MIT or Apache-2.0 at your option.
See `LICENSE-MIT` and `LICENSE-APACHE` at the repo root.

The BPF program (`linprov-ebpf`) declares `Dual MIT/GPL` in its
`license` ELF section so the kernel verifier accepts it as
GPL-compatible — required for the `bpf_d_path` and `bpf_get_file_xattr`
helpers, which are `gpl_only`. The source itself is the same
MIT-OR-Apache-2.0 as the rest of the workspace; the GPL token is a
license-compatibility statement to the kernel, not a relicense.

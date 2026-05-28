# linprov

eBPF-based mark-of-the-web for Linux. Every file written by a process that
touched the network gets tagged with a provenance xattr; every `execve` of
a tagged file is logged, and — optionally — blocked unless the path is on
an explicit allowlist.

## How it works

Three sleepable BPF LSM hooks plus one cleanup tracepoint:

| Hook | What it does |
|---|---|
| `socket_post_create` | First time a PID creates an `AF_INET`/`AF_INET6` socket, mark the PID as network-touched in an LRU hash map. |
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

## Build

```
cargo build --release
```

Requires `bpf-linker` (`cargo install bpf-linker`). Depends on a
[forked aya](https://github.com/FridayOrtiz/aya) that adds kfunc
relocation resolution; the dependency is resolved by git
automatically — no local checkout required.

Install from a git checkout works today:

```
cargo install --git https://github.com/FridayOrtiz/linprov linprov
```

`cargo install linprov` from crates.io is blocked on publishing the
renamed aya fork (`aya-friday-*`). Once those crates land, plain
`cargo install linprov` is self-contained — the linprov tarball ships
the BPF source, the `rust-toolchain.toml`, and everything else
`build.rs` needs.

## Tests

```
# Unit tests + doctests (no kernel needed):
cargo test --workspace --exclude linprov-ebpf

# Smoke suite (needs root + BPF LSM kernel; see tests/README.md):
cargo build
sudo ./tests/smoke/run-all.sh
```

## Run

Three modes. The `--allowlist` file format is described
[below](#allowlist-format).

### Observe (default)

Marks files and logs marked execs. Never blocks.

```
sudo ./target/release/linprov
```

Sample log line for an exec of a marked binary:

```
PROVENANCE-EXEC path=/tmp/curl-download pid=12345 comm=zsh \
  origin={v:2,ts_boot_ns:42…,pid:6789,uid:1000,comm:curl,path:/usr/bin/curl}
```

### Soak

Like observe, but every PROVENANCE-EXEC produces allowlist rules for the
dimensions selected by `--soak`. Defaults to `creator_process`.

```
# Default: one rule per distinct creator binary
sudo ./target/release/linprov --mode soak --allowlist /etc/linprov.allow

# Capture multiple dimensions per event
sudo ./target/release/linprov --mode soak --allowlist /etc/linprov.allow \
    --soak creator_process,creator_uid,target_folder
```

Tail the allowlist file as soak runs to watch the policy build up. Rules
are deduplicated on the literal text, so re-execing the same files just
no-ops.

### Enforce

Loads the allowlist into BPF maps at startup. A marked execve is permitted
iff *any* rule in the allowlist matches the file's `OriginRecord` (creator
identity / UID / etc.) or the target path. Unmarked binaries are never
touched.

```
sudo ./target/release/linprov --mode enforce --allowlist /etc/linprov.allow
```

Blocked exec log:

```
BLOCKED-EXEC path=/tmp/sketchy pid=12346 comm=zsh \
  origin={v:2,…,comm:curl,path:/usr/bin/curl} (LSM verdict -1)
```

The originating shell sees `Operation not permitted` and `$?` is 126.

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

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

This depends on a [forked aya](https://github.com/FridayOrtiz/aya) that
adds kfunc relocation resolution. The dependency is resolved by git
automatically; no local checkout required.

## Run

Three modes. The `--allowlist` file is one absolute path per line, `#`
starts a comment, blank lines ignored.

### Observe (default)

Marks files and logs marked execs. Never blocks. Use this for understanding
what your system does over time.

```
sudo ./target/release/linprov
```

Sample log line for an exec of a marked binary:

```
PROVENANCE-EXEC path=/tmp/curl-download pid=12345 comm=zsh \
  origin={v:1,ts_boot_ns:42…,pid:6789,comm:curl}
```

### Soak

Same observation as above, but every distinct PROVENANCE-EXEC path is
appended to the allowlist file. Use to generate the allowlist you'll later
feed to enforce.

```
sudo ./target/release/linprov --mode soak --allowlist /etc/linprov.allow
```

Tail the file as you go to watch the policy build up.

### Enforce

Loads the allowlist into a BPF hash map at startup. Marked execs whose path
is on the list are permitted as normal; everything else is blocked with
`-EPERM` from `security_bprm_check`. Unmarked binaries are never touched.

```
sudo ./target/release/linprov --mode enforce --allowlist /etc/linprov.allow
```

Blocked exec log:

```
BLOCKED-EXEC path=/tmp/sketchy pid=12346 comm=zsh \
  origin={v:1,…,comm:curl} (LSM verdict -1)
```

The originating shell sees `Operation not permitted` and `$?` is 126.

## Inspecting the xattr by hand

```
getfattr -d -m '.*' /path/to/file
# security.bpf.linprov.origin=0sAQAAAA...
```

The value is 32 bytes of binary `OriginRecord`: `version (4) | pid (4) |
ts_boot_ns (8) | comm[16]`. Use `od -An -tx1` if you want to decode it
manually; the daemon's log lines already format it.

## Roadmap

These are deliberately not in main yet — listed here so anyone picking up
the repo knows where it's going.

- **Archive-aware provenance.** The mark currently lives on a single inode.
  If you `tar xf` or `unzip` a marked archive, the extracted files come out
  unmarked. Hook tar/zip in userspace (FUSE? `inotify`? ld-preload on
  `libarchive`?) or — better — extend the BPF program to track inode
  derivation through `inode_create` when the creating process is reading a
  marked file.
- **Script support.** Today only ELF binaries trigger the exec hook in a
  useful way. `#!/usr/bin/env python` runs Python on a marked script, but
  it's Python that the exec hook sees — not the script. Want to read the
  script's xattr in `inode_permission` (or a userspace shebang-aware
  wrapper) so script execution honors the same enforce policy.
- **Richer allowlist matching.** Right now an entry is a full path. Add
  rules keyed by:
  - `origin.comm` (creator process name — allow anything written by
    `apt-get`)
  - `origin.uid` (write-time UID)
  - executing UID (only allow `root` to run marked things)
  - path globs / prefixes (allow `/opt/installed/**`)
  
  The OriginRecord schema is versioned; bumping it to add UIDs is the
  easy part.
- **In-kernel xattr WRITE.** The `bpf_set_dentry_xattr` kfunc carries
  `KF_TRUSTED_ARGS` and `file->f_path.dentry` isn't on the verifier's
  safe-trusted list, so we can't call it from `file_open`. Either get a
  kernel patch into `BTF_TYPE_SAFE_TRUSTED(struct file)`, or use a
  per-write dentry-bearing LSM hook (none currently fire on byte-level
  writes). Until then, the userspace setxattr round-trip stays. The
  same-boot race is already closed by the inode_storage path; this is
  just about lowering the persistence cost.
- **Publishable crate UX.** When this is ready to ship as a crate:
  - Startup feature detection (vmlinux BTF present, BPF LSM in the
    active list, kernel version ≥ 6.5) with clear failure messages.
  - `linprov install` to drop a systemd unit.
  - Guided soak workflow: run for N hours observing, emit a summary
    proposing the allowlist.
  - Control socket / SIGHUP allowlist reload without restarting (current
    behavior requires daemon restart to update the BPF map).
- **xattr-stripping resistance.** Out of scope; assumed-cooperative
  filesystem. A motivated user with `setfattr -x` can clear the mark.

## Repository layout

```
linprov/         userspace daemon (clap, tokio, aya)
linprov-ebpf/    BPF programs (no_std, aya-ebpf, inline asm for kfuncs)
linprov-common/  types shared between the two
```

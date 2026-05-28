# Roadmap

Things deliberately not in `main` yet — recorded here so anyone
picking up the repo knows where it's going.

## Provenance scope

- **Archive-aware provenance.** The mark currently lives on a single
  inode. If you `tar xf` or `unzip` a marked archive, the extracted
  files come out unmarked. Hook tar/zip in userspace (FUSE? `inotify`?
  LD_PRELOAD on `libarchive`?) or — better — extend the BPF program to
  track inode derivation through `inode_create` when the creating
  process is reading a marked file.
- **Script support.** Today only ELF binaries trigger the exec hook in
  a useful way. `#!/usr/bin/env python` runs Python on a marked
  script, but it's Python that the exec hook sees — not the script.
  Want to read the script's xattr in `inode_permission` (or a
  userspace shebang-aware wrapper) so script execution honors the same
  enforce policy.
- **In-kernel xattr WRITE.** The `bpf_set_dentry_xattr` kfunc carries
  `KF_TRUSTED_ARGS` and `file->f_path.dentry` isn't on the verifier's
  safe-trusted list, so we can't call it from `file_open`. Either get
  a kernel patch into `BTF_TYPE_SAFE_TRUSTED(struct file)`, or use a
  per-write dentry-bearing LSM hook (none currently fire on byte-level
  writes). Until then, the userspace setxattr round-trip stays. The
  same-boot race is already closed by the inode_storage path; this is
  just about lowering the persistence cost.
- **xattr-stripping resistance.** Out of scope; assumed-cooperative
  filesystem. A motivated user with `setfattr -x` can clear the mark.
- **Accept side of the network signal.** Today we only mark on
  outgoing `connect()`. A process that `accept()`s an inbound
  connection and writes a file based on that data doesn't get its
  PID marked. Probably want a parallel `socket_accept` LSM hook with
  the same loopback-skip rule.

## Allowlist

- **Bigger rule set.** `MAX_RULES = 32` today because each rule's
  conditions are walked per execve and the kernel verifier caps the
  per-program-load instruction count at 1M. The current bottleneck is
  re-walking path-shaped dims for each rule. Folding into a single
  pre-pass + bitset lookup would scale beyond 32, but the pre-pass
  itself exploded the verifier (per-byte conditional stores). A
  `bpf_loop`-based path scan would sidestep this.
- **Path globs** (`/opt/installed/*.so`) — currently exact paths and
  recursive folder prefixes only.
- **LPM-trie folder match.** FNV hashing works but it's exact-prefix.
  LPM trie isn't allowed in sleepable programs; if we ever split exec
  enforcement into non-sleepable allowlist + sleepable xattr fetch, an
  LPM trie becomes viable.

## Operability

- **Guided soak interval inside `linprov setup`.** Today `setup` is
  the install-time path: feature-check, drop a systemd unit, write
  defaults. A follow-up: an interactive flow that enables the unit in
  `soak` mode, watches for N hours / executions, and proposes the
  resulting allowlist for review before flipping to `enforce`.
- **Ad-hoc allow at block time.** Every `BLOCKED-EXEC` log line emits
  a short stable token. `linprov allow <token>` appends a rule that
  would have permitted that exec to the allowlist file and signals
  the daemon to hot-reload (SIGHUP or inotify). No daemon restart
  required.
- **Hot reload.** SIGHUP re-parses the allowlist file and re-seeds
  the BPF rules map.

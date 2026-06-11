# Roadmap

Planned work and open design questions — what's *not* in `main` yet.
Shipped behavior is documented in the [README](README.md); this file is
only the road ahead.

## Provenance scope

- **In-kernel xattr WRITE.** The `bpf_set_dentry_xattr` kfunc carries
  `KF_TRUSTED_ARGS` and `file->f_path.dentry` isn't on the verifier's
  safe-trusted list, so we can't call it from `file_open`. Either get
  a kernel patch into `BTF_TYPE_SAFE_TRUSTED(struct file)`, or use a
  per-write dentry-bearing LSM hook (none currently fire on byte-level
  writes). Until then, the userspace setxattr round-trip stays. The
  same-boot race is already closed by the inode_storage path; this is
  just about lowering the persistence cost.
- **Accept side of the network signal.** Today we only mark on
  outgoing `connect()`. A process that `accept()`s an inbound
  connection and writes a file based on that data doesn't get its
  PID marked. Probably want a parallel `socket_accept` LSM hook with
  the same loopback-skip rule.
- **Harden interpreter matching against `comm` spoofing.** Script
  enforcement matches interpreters by `comm`, which the kernel truncates
  to 15 bytes and a process can rename. Fine for cooperative environments;
  an exe-path-hash variant (a `bpf_d_path` of the reader's exe, matched
  like `creator_process`) would harden it at a hot-path cost.
- **xattr-stripping resistance.** A deliberate non-goal: linprov assumes
  a cooperative filesystem, so a motivated user with `setfattr -x` can
  clear the mark. Recorded here so it's a known boundary, not an oversight.

## Allowlist

- **Infix path globs.** Exact paths and recursive folder prefixes
  (`target_folder=/opt/app/*`) are supported; infix globs like
  `/opt/installed/*.so` are not. Matching walks `/`-delimited hash
  prefixes, so a mid-path wildcard needs a different scheme.
- **LPM-trie folder match.** FNV hashing works but it's exact-prefix.
  LPM trie isn't allowed in sleepable programs; if we ever split exec
  enforcement into a non-sleepable allowlist + sleepable xattr fetch, an
  LPM trie becomes viable.

## Operability

- **Guided soak interval inside `linprov setup`.** `setup` is already
  interactive, but the soak *duration* is left to the user. A follow-up:
  `setup` could supervise a timed / N-execution soak and propose the
  resulting allowlist for review before flipping to `enforce`.

## Desktop tray agent

- **[Quarantine] menu action.** *Partially landed* — the tray menu
  reserves the slot, but the action isn't wired up. A fourth choice that
  neutralizes the file instead of allowing it: move it to a quarantine
  directory (stops exec *and* interpreter-read) and record the origin so
  it can be restored. Needs a new daemon `quarantine <token>`
  control-socket verb + policy (destination, restore path).

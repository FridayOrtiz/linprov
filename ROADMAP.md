# Roadmap

Things deliberately not in `main` yet — recorded here so anyone
picking up the repo knows where it's going.

## Provenance scope

- **Archive-aware provenance.** *Landed (same-boot).* A process that
  **reads** a marked inode is tainted (`PROP_PIDS`); files it later
  **writes** inherit the source's `OriginRecord` with their own landing
  hashes. So `tar xf` / `unzip` of a marked archive marks the extracted
  files, and `cp` of a marked file propagates too. Implemented in
  `file_open` (read branch taints, write branch inherits) — no separate
  `inode_create` hook needed. Remaining work:
  - **Cross-boot.** Taint reads only the in-kernel `INODE_MARKS` map (one
    cheap lookup on the hot read path), so an archive whose mark survives
    only as an xattr (downloaded a previous boot, inode-storage evicted)
    won't propagate. Reading the xattr via the `bpf_get_file_xattr` kfunc
    on every non-write open would close this but is a real cost on the
    kernel's busiest path — deferred.
  - **`creator_path_hash` race.** Userspace back-fills the augmented record
    (with the resolved creator exe-path hash) into `INODE_MARKS` after
    marking, so inheritance normally carries the full creator identity. But
    if extraction beats that async back-fill, the derived file inherits
    `creator_path_hash == 0` (creator `comm`/uid/pid/ts still propagate) —
    same best-effort timing as the xattr.
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

- **Bigger rule set.** `MAX_RULES = 32` today. The `bpf_loop`-based
  path scan that this entry used to propose as future work has since
  landed (`linprov-ebpf/src/main.rs`: the FNV walks run inside a
  `bpf_loop` callback via helper 181, kernel >= 5.17) — the verifier
  now inspects the callback once instead of unrolling the loop body
  across every rule × dim. That removed the verifier-amortization
  blocker, but the 32-rule ceiling itself has not moved. Pushing past
  32 still wants the single pre-pass + bitset lookup (the naive
  per-byte conditional-store version exploded the verifier).
- **Path globs.** Recursive folder matching via a trailing `*`
  (`target_folder=/opt/app/*` → `TARGET_FOLDER_RECURSIVE`, matches the
  folder or any descendant) has landed. Still missing: infix globs
  like `/opt/installed/*.so`. Today's rules are exact paths and
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
- **Ad-hoc allow at block time.** Not yet implemented. The design:
  have every `BLOCKED-EXEC` log line emit a short stable token, then a
  `linprov allow <token>` subcommand that appends a rule which would
  have permitted that exec to the allowlist file and signals the
  daemon to hot-reload (SIGHUP or inotify). No daemon restart
  required. (Today `BLOCKED-EXEC` logs full context but no token, and
  there is no `allow` subcommand.)
- **Hot reload.** SIGHUP re-parses the allowlist file and re-seeds
  the BPF rules map.

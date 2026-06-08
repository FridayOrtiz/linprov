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
  - **Cross-boot.** *Landed* (alongside script support). The `file_open`
    read branch now falls back to the `bpf_get_file_xattr` kfunc when
    `INODE_MARKS` misses, and **promotes** the on-disk record back into
    `INODE_MARKS` — so an archive whose mark survives only as an xattr
    (downloaded a previous boot, inode-storage evicted) propagates, and
    the kfunc cost is paid once per inode per boot rather than on every
    read. The trade-off the earlier note worried about is real but
    bounded: the very first read of each previously-unseen inode now does
    one (usually `-ENODATA`) xattr probe.
  - **`creator_path_hash` race.** Userspace back-fills the augmented record
    (with the resolved creator exe-path hash) into `INODE_MARKS` after
    marking, so inheritance normally carries the full creator identity. But
    if extraction beats that async back-fill, the derived file inherits
    `creator_path_hash == 0` (creator `comm`/uid/pid/ts still propagate) —
    same best-effort timing as the xattr.
- **Script support.** *Landed.* Shebang scripts (`./foo.sh`) were
  always enforced — the kernel runs `bprm_check_security` on the script
  file itself (depth 0 of `exec_binprm`, before binfmt_script swaps in
  the interpreter). The gap was the *interpreter-invoked* form —
  `bash foo.sh`, `python foo.py`, `. foo.sh` — where the kernel only
  execve's the unmarked interpreter and the script reaches it as an
  ordinary `open()`, never `bprm_check`. Now the `file_open` read branch
  recognizes a known interpreter (configurable `comm` set, `INTERPRETERS`
  map — bash/sh/python/perl/node/…) reading a *marked* file and runs the
  same `check_allowlist` against the script's path, denying with
  `-EPERM` when not permitted. So a rule keyed on the script
  (`target_filename=/x/script.py`, `target_folder=/x/`) permits both the
  interpreter and shebang forms identically. Remaining edges:
  - **Interpreter reading marked *data*.** Once an interpreter is cleared
    to run an approved (allowlisted) script, its PID is recorded in
    `APPROVED_INTERP` and its *later* marked reads pass — so an allowlisted
    script may open its own marked data files, exactly as an allowlisted
    ELF reads marked files freely. The allowlist check (and the SCRIPT
    event) therefore fire only on the first marked read per interpreter
    invocation: the script itself. The residual case is an interpreter
    reading a marked file *without* having been cleared to run a script —
    an interactive `python` opening a marked `.json`, or a local/unmarked
    script reading marked data — which is still denied (the kernel can't
    tell code from data). Mitigated by the allowlist and by
    narrowing/emptying the interpreter set (an empty set disables script
    enforcement). The grant lasts the interpreter's lifetime: approved
    (trusted) code may then read/source any marked file — consistent with
    how an approved ELF is unrestricted, and the same reason
    `exec(open(...).read())`-style in-process loading can't be caught at
    the VFS layer regardless.
  - **comm spoofing/truncation.** Interpreters are matched by `comm`,
    which the kernel truncates to 15 bytes and which a process can
    rename. Fine for cooperative environments; an exe-path-hash variant
    (a `bpf_d_path` of the reader's exe) would harden it at a hot-path
    cost.
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

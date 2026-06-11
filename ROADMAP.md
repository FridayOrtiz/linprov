# Roadmap

Where linprov is and where it's going. Entries are tagged **_Landed_**
(already in `main`) or describe work still planned — so anyone picking up
the repo can tell at a glance what exists versus what's aspirational.

## Provenance scope

- **Archive-aware provenance.** *Landed (same-boot **and** cross-boot).* A
  process that **reads** a marked inode is tainted (`PROP_PIDS`); files it
  later **writes** inherit the source's `OriginRecord` with their own landing
  hashes. So `tar xf` / `unzip` of a marked archive marks the extracted
  files, and `cp` of a marked file propagates too. Implemented in
  `file_open` (read branch taints, write branch inherits) — no separate
  `inode_create` hook needed.
  - **Cross-boot.** *Landed* (alongside script support). The `file_open`
    read branch falls back to the `bpf_get_file_xattr` kfunc when
    `INODE_MARKS` misses, and **promotes** the on-disk record back into
    `INODE_MARKS` — so an archive whose mark survives only as an xattr
    (downloaded a previous boot, inode-storage evicted) still propagates,
    and the kfunc cost is paid once per inode per boot rather than on every
    read. Cost: the first read of each previously-unseen inode does one
    (usually `-ENODATA`) xattr probe.
  - **Caveat — `creator_path_hash` race.** Userspace back-fills the
    augmented record (with the resolved creator exe-path hash) into
    `INODE_MARKS` after marking, so inheritance normally carries the full
    creator identity. But if extraction beats that async back-fill, the
    derived file inherits `creator_path_hash == 0` (creator `comm`/uid/pid/ts
    still propagate) — same best-effort timing as the xattr. A known
    limitation, not pending work.
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
  - **Pseudo-fs exclusion.** `/dev`, `/proc`, `/sys`, `/run` are never
    marked (the eBPF write branch skips them, mirroring userspace
    `is_pseudo_fs`). Without this a net-touched process writing to
    `/dev/null` — which everything does — marked its inode, and then any
    interpreter reading `/dev/null` (every shell, every `2>/dev/null`) was
    denied in enforce mode, wedging the box. Found by dogfooding.
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

- **Bigger rule set.** *Landed — `MAX_RULES = 8192`* (256× the old 32).
  The per-rule scan now runs inside a single `bpf_loop` callback
  (`allow_step`) over a precomputed `AllowCtx`, so the verifier inspects
  the rule body **once** instead of unrolling it across every rule — load
  time is O(1) in `MAX_RULES` (~0.45s flat from 256 to 8192) and per-execve
  cost is bounded by the *actual* rule count, not the ceiling. The old
  unrolled loop (with an `fnv_full`/`folder_match` walk inside each
  iteration) topped out below 64 rules against the 1M-instruction budget.
  The "single pre-pass" this entry used to call for is exactly that
  precompute: the live exec path's full / parent / ancestor-prefix hashes
  are computed once (`target_hashes` → the per-CPU `TARGET_ANCESTORS` map)
  so the rule loop is walk-free. Two notes:
  - Recursive `target_folder` now matches via the precomputed ancestor
    array, so it's capped at `MAX_FOLDER_ANCESTORS` (32) levels — same cap
    the landing side already had; the old per-rule `folder_match` walked to
    `PATH_MAX`. No real exec path nests 32 dirs deep.
  - An over-capacity allowlist no longer crash-loops the daemon: startup
    and SIGHUP reload load the first `MAX_RULES` and warn (`check_capacity`),
    and soak stops appending at the ceiling. (A long soak run had grown
    `list.allow` past the old 32-rule limit and bricked the next restart.)
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

- **Interactive `linprov setup`.** *Landed.* On a TTY, `setup` walks
  through the observe → soak → enforce model and, on a detected graphical
  session, offers to set up the desktop tray UI end-to-end: enable
  `notifications = "tray"`, add the invoking user to the `linprov` group,
  and install + enable a `systemd --user` service that autostarts
  `linprov notify`. Every change is gated on a y/n prompt; `--yes` (or a
  non-TTY stdin) keeps the old non-interactive behavior. Still a follow-up:
  a **guided soak interval** — `setup` could supervise a timed / N-execution
  soak and propose the resulting allowlist for review before flipping to
  `enforce`, rather than leaving the soak duration to the user.
- **Hot reload.** *Landed.* `SIGHUP` re-parses the allowlist file and
  re-seeds the BPF `ALLOW_RULES` / `ALLOW_RULE_COUNT` maps in place — no
  daemon restart, no LSM re-attach. An unreadable/unparseable file leaves
  the live rules untouched (the error propagates before the map is
  written); an over-`MAX_RULES` file warns and applies the first
  `MAX_RULES`. Shrinking the rule set just lowers `ALLOW_RULE_COUNT` — the
  BPF side reads only that many slots, so stale tail slots are never
  consulted (no clear needed). Only the allowlist is reloaded — mode,
  interpreter set, and other launch config stay as started.
- **Ad-hoc allow at block time.** *Landed.* Every `BLOCKED-EXEC` /
  `BLOCKED-SCRIPT` line ends with `[allow: <token>]`, a short stable hash
  of the most-specific rule that would have permitted that exec.
  `linprov allow <token>` asks the daemon (over a root-only unix control
  socket, `/run/linprov/control.sock`) to apply that rule and reseed the
  live map. Plain `allow` appends it to the allowlist file (permanent);
  `allow --once` adds it to the daemon's in-memory transient set instead —
  active immediately and across SIGHUP reloads, never written to disk, and
  gone on daemon restart. The daemon holds a bounded in-memory table of
  recent block tokens (per-session: a token from before a restart won't
  resolve — re-trigger the exec for a fresh one). Requires the daemon
  running; if it's down, hand-editing the file + SIGHUP is the offline
  path.

## Desktop tray agent (interactive approvals)

*Landed* (except `[Quarantine]`). `linprov notify` is a user-session tray
agent: it shows a StatusNotifierItem icon whose context menu lists recent
blocked execs, each with **Allow once / Allow always / Close**, and fires a
passive desktop notification per block as an alert. (We chose a tray over
`mako` notification *actions* — mako has no inline buttons, only
`makoctl menu`, so it's awkward and non-portable; SNI is served by waybar's
tray on sway and works across desktops.)

- **Off by default.** `notifications = "off" | "tray"` (default `off`).
  `off` keeps the control socket root-only (headless). `tray` chmods it
  0660 group `linprov` so the user-session agent can connect.
- **Reuses the allow plumbing.** The daemon streams block events to
  `subscribe`rs over the control socket (`BLOCK\t<token>\t<kind>\t<target>\t<creator>`);
  menu clicks drive the existing verbs — Allow once → `once <token>`
  (transient), Allow always → `allow <token>` (persistent), Close →
  dismiss locally.
- **Privilege boundary.** The daemon is root on the *system* bus; the tray
  is on the user's *session* bus. The agent (run as the user from the sway
  config — `exec linprov notify`) bridges them: it reaches the daemon via
  the group-readable control socket and pops the tray/notifications on the
  session bus. Needs a StatusNotifierHost (waybar's tray on sway).
- **Enforcement stays synchronous.** The LSM hook denies the exec with
  `-EPERM` *before* the agent ever sees it — so the prompt is post-hoc:
  Allow permits the *next* attempt (the user re-runs), not the one that
  just failed. A "hold the exec until the user decides" gate isn't feasible
  from the hook.
- **[Quarantine] (still to do).** A fourth menu action that neutralizes the
  file instead of allowing it — move it to a quarantine directory (stops
  exec *and* interpreter-read) + record the origin so it can be restored.
  Needs a new daemon `quarantine <token>` control-socket verb + policy
  (destination, restore path); the tray menu reserves the slot.

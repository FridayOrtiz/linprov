//! Ring-buffer event handler.
//!
//! `NetworkFileOpen` events: read `/proc/$pid/exe` to learn the creator's
//! full exe path, record the path → hash mappings (creator exe, landing
//! folder, landing basename) in the audit db, then write the augmented
//! v4 `OriginRecord` (all hashes) to the `security.bpf.linprov.origin`
//! xattr.
//!
//! `Execve` events (only emitted when the file was marked): log; in
//! enforce mode the LSM verdict in `event.status` tells us whether the
//! exec was blocked; in soak mode we emit one allowlist rule per
//! configured dimension, resolving the record's hashes back to paths via
//! the audit db.

use std::{
    fs,
    path::{Path, PathBuf},
};

use linprov_common::{
    Event, OriginRecord, COMM_LEN, EVENT_KIND_DERIVED_FILE_OPEN, EVENT_KIND_EXECVE,
    EVENT_KIND_NETWORK_FILE_OPEN, EVENT_KIND_SCRIPT_EXEC, EXEC_PATH_LEN, MAX_FOLDER_ANCESTORS,
    ORIGIN_VERSION, XATTR_NAME,
};
use log::{debug, info, warn};

use crate::{
    allowlist::{rule_from_context, OriginContext, Soak, ALLOW_DIMS},
    control::BlocksTable,
    hashdb::HashDb,
    inode_storage::InodeMarks,
    ModeArg,
};

pub struct Config<'a> {
    pub mode: ModeArg,
    pub soak: Option<Soak>,
    pub hashdb: &'a HashDb,
}

pub fn handle_event(
    cfg: &Config,
    inode_marks: &mut InodeMarks,
    blocks: &mut BlocksTable,
    raw: &[u8],
) {
    if raw.len() < std::mem::size_of::<Event>() {
        warn!(
            "short ring-buf record: got {} bytes, expected {}",
            raw.len(),
            std::mem::size_of::<Event>()
        );
        return;
    }
    let event: &Event =
        match bytemuck::try_from_bytes::<Event>(&raw[..std::mem::size_of::<Event>()]) {
            Ok(e) => e,
            Err(e) => {
                warn!("failed to cast ring-buf record to Event: {e}");
                return;
            }
        };

    match event.kind {
        EVENT_KIND_NETWORK_FILE_OPEN => on_file_marked(cfg, inode_marks, event, false),
        EVENT_KIND_DERIVED_FILE_OPEN => on_file_marked(cfg, inode_marks, event, true),
        EVENT_KIND_EXECVE => on_execve_marked(cfg, blocks, event),
        EVENT_KIND_SCRIPT_EXEC => on_script_exec(cfg, blocks, event),
        other => warn!("unknown event kind: {other}"),
    }
}

/// Handle a file-marked event. `derived == false` for a network-touched
/// write (the writer is the creator → resolve its exe path); `derived ==
/// true` for a taint-propagated write (e.g. `tar` extracting a marked
/// archive → the record's creator identity is *inherited* and must not be
/// overwritten with the extractor's exe).
fn on_file_marked(cfg: &Config, inode_marks: &mut InodeMarks, event: &Event, derived: bool) {
    let landing_path = c_str_to_string(&event.filename);
    let comm = comm_to_string(&event.comm);
    let target = PathBuf::from(&landing_path);

    if is_pseudo_fs(&target) {
        debug!("skipping non-regular target: {}", target.display());
        return;
    }

    // Start from the BPF-written record (landing hashes already set on the
    // in-kernel storage copy) and fill in what only userspace can resolve.
    let mut augmented: OriginRecord = event.origin;
    augmented.version = ORIGIN_VERSION;

    // Record path → hash mappings in the audit db, and set the same hashes
    // on the record we persist. `HashDb::record` hashes with the same
    // FNV the BPF side uses, so these match the in-kernel storage record
    // (and the allowlist rule hashes).
    //
    // Ancestor hashes (shallow → deep) for nested landing_folder
    // matching — mirrors the BPF walk, including the power-of-two index
    // mask, so the userspace-written xattr and the in-kernel
    // inode_storage record agree byte-for-byte.
    augmented.landing_ancestor_hashes = [0u64; MAX_FOLDER_ANCESTORS];
    let mut count = 0usize;
    for (i, b) in landing_path.bytes().enumerate() {
        if b == b'/' {
            let prefix = &landing_path[..=i]; // includes the trailing '/'
            let h = cfg.hashdb.record(prefix);
            augmented.landing_ancestor_hashes[count & (MAX_FOLDER_ANCESTORS - 1)] = h;
            count += 1;
            // The deepest `/`-prefix is the immediate parent.
            augmented.landing_folder_hash = h;
        }
    }
    if let Some(base) = basename_of(&landing_path) {
        augmented.landing_basename_hash = cfg.hashdb.record(base);
    }

    // Resolve the creator's exe path — but only for fresh (network) marks.
    //
    //   * network: /proc/$pid/exe is the binary the creator was exec'd from.
    //     Best-effort: if the creator already exited we leave
    //     creator_path_hash at 0, and rules keyed on it just won't match.
    //   * derived: the marking process is the *extractor* (e.g. tar), not the
    //     creator — the creator identity is inherited from the source file's
    //     record and must be kept as-is. We only resolve the already-set
    //     hash for the log line.
    let creator_path = if derived {
        cfg.hashdb.resolve(augmented.creator_path_hash)
    } else {
        let p = read_creator_exe(event.pid);
        if let Some(path) = p.as_deref() {
            augmented.creator_path_hash = cfg.hashdb.record(path);
        }
        p
    };

    let value = bytemuck::bytes_of(&augmented).to_vec();
    let kind = if derived {
        "marked (derived)"
    } else {
        "marked"
    };

    // Marking a written file is routine and high-volume; log it at DEBUG.
    // INFO is reserved for actual executions (the PROVENANCE-EXEC line in
    // `on_execve_marked`).
    match xattr::set(&target, XATTR_NAME, &value) {
        Ok(()) => debug!(
            "{kind} {} (pid={} comm={} creator_uid={} creator_path={} ts_boot_ns={})",
            target.display(),
            event.pid,
            comm,
            augmented.creator_uid,
            creator_path.as_deref().unwrap_or("<unknown>"),
            event.origin.ts_boot_ns
        ),
        Err(e) => debug!("setxattr({}, {XATTR_NAME}) failed: {e}", target.display()),
    }

    // Back-fill the in-kernel INODE_MARKS record with the augmented record so
    // the bprm fast path (which otherwise re-reads the xattr when
    // creator_path_hash == 0) and same-boot taint propagation both carry the
    // full creator identity. Best-effort.
    backfill_inode_mark(inode_marks, &target, &augmented);
}

/// Open `target` `O_PATH` (which does *not* fire `security_file_open`, so it
/// can't re-taint the daemon) and update its `INODE_MARKS` record. Failures
/// (file renamed/removed between the event and now, fs without inode storage
/// support, etc.) are non-fatal — the durable xattr is already written.
fn backfill_inode_mark(inode_marks: &mut InodeMarks, target: &Path, rec: &OriginRecord) {
    use std::os::unix::fs::OpenOptionsExt;

    // read(true) only satisfies std's "an access mode is required"; O_PATH
    // overrides it in the kernel, yielding a path-only fd we use purely as
    // the inode-storage key.
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(target)
    {
        Ok(f) => {
            if let Err(e) = inode_marks.backfill(&f, rec) {
                debug!("INODE_MARKS back-fill for {} failed: {e}", target.display());
            }
        }
        Err(e) => debug!(
            "O_PATH open of {} for INODE_MARKS back-fill failed: {e}",
            target.display()
        ),
    }
}

fn read_creator_exe(pid: u32) -> Option<String> {
    let link = format!("/proc/{pid}/exe");
    match fs::read_link(&link) {
        Ok(p) => Some(p.to_string_lossy().into_owned()),
        Err(e) => {
            debug!("read_link({link}) failed: {e}");
            None
        }
    }
}

fn is_pseudo_fs(target: &std::path::Path) -> bool {
    let Some(s) = target.to_str() else {
        return true;
    };
    s.starts_with("/dev/")
        || s.starts_with("/proc/")
        || s.starts_with("/sys/")
        || s.starts_with("/run/")
}

fn on_execve_marked(cfg: &Config, blocks: &mut BlocksTable, event: &Event) {
    let target_path = c_str_to_string(&event.filename);
    let exec_comm = comm_to_string(&event.comm);
    let creator_comm = comm_to_string(&event.origin.comm);

    // Resolve the record's hashes back to human-readable paths via the
    // audit db. `None` means the db doesn't know this hash (e.g. it was
    // pruned, or the creator exited before it could be recorded).
    let creator_path = cfg.hashdb.resolve(event.origin.creator_path_hash);
    let landing_folder = cfg.hashdb.resolve(event.origin.landing_folder_hash);
    let landing_basename = cfg.hashdb.resolve(event.origin.landing_basename_hash);

    if event.status != 0 {
        let token = record_block_token(
            blocks,
            event,
            &target_path,
            &landing_folder,
            &landing_basename,
            &creator_path,
            &creator_comm,
        );
        warn!(
            "BLOCKED-EXEC target={} landing_folder={} landing_file={} pid={} comm={} origin={} (LSM verdict {}) [allow: {token}]",
            target_path,
            resolved(&landing_folder, event.origin.landing_folder_hash),
            resolved(&landing_basename, event.origin.landing_basename_hash),
            event.pid,
            exec_comm,
            format_origin(&event.origin, &creator_comm, &creator_path),
            event.status,
        );
        return;
    }

    info!(
        "PROVENANCE-EXEC target={} landing_folder={} landing_file={} pid={} comm={} origin={}",
        target_path,
        resolved(&landing_folder, event.origin.landing_folder_hash),
        resolved(&landing_basename, event.origin.landing_basename_hash),
        event.pid,
        exec_comm,
        format_origin(&event.origin, &creator_comm, &creator_path),
    );

    maybe_soak(
        cfg,
        event,
        &target_path,
        &landing_folder,
        &landing_basename,
        &creator_path,
        &creator_comm,
    );
}

/// Handle a script-exec event: a marked file opened for read by a known
/// interpreter (`bash foo.sh` / `python foo.py` / `. foo.sh`). The script
/// — not the interpreter — is the unit: `event.filename` is the script
/// path and drives allowlist matching exactly like an execve; the
/// interpreter's `comm` is carried for context. `status != 0` means the
/// LSM denied the read (enforce). Mirrors `on_execve_marked`, including
/// soak rule emission keyed on the script path, so a
/// `target_filename=<script>` / `target_folder=<dir>` rule permits the
/// script under any interpreter and under `./script` (shebang) alike.
fn on_script_exec(cfg: &Config, blocks: &mut BlocksTable, event: &Event) {
    let script_path = c_str_to_string(&event.filename);
    let interp_comm = comm_to_string(&event.comm);
    let creator_comm = comm_to_string(&event.origin.comm);

    let creator_path = cfg.hashdb.resolve(event.origin.creator_path_hash);
    let landing_folder = cfg.hashdb.resolve(event.origin.landing_folder_hash);
    let landing_basename = cfg.hashdb.resolve(event.origin.landing_basename_hash);
    let script_name = basename_of(&script_path).unwrap_or(&script_path);

    if event.status != 0 {
        let token = record_block_token(
            blocks,
            event,
            &script_path,
            &landing_folder,
            &landing_basename,
            &creator_path,
            &creator_comm,
        );
        warn!(
            "BLOCKED-SCRIPT script={} name={} interp={} landing_folder={} landing_file={} pid={} origin={} (LSM verdict {}) [allow: {token}]",
            script_path,
            script_name,
            interp_comm,
            resolved(&landing_folder, event.origin.landing_folder_hash),
            resolved(&landing_basename, event.origin.landing_basename_hash),
            event.pid,
            format_origin(&event.origin, &creator_comm, &creator_path),
            event.status,
        );
        return;
    }

    info!(
        "PROVENANCE-SCRIPT script={} name={} interp={} landing_folder={} landing_file={} pid={} origin={}",
        script_path,
        script_name,
        interp_comm,
        resolved(&landing_folder, event.origin.landing_folder_hash),
        resolved(&landing_basename, event.origin.landing_basename_hash),
        event.pid,
        format_origin(&event.origin, &creator_comm, &creator_path),
    );

    maybe_soak(
        cfg,
        event,
        &script_path,
        &landing_folder,
        &landing_basename,
        &creator_path,
        &creator_comm,
    );
}

/// Build the candidate "allow" rule for a blocked exec (the most-specific
/// rule that would have permitted it — see `ALLOW_DIMS`), record it in the
/// blocks table, and return its stable token. The token goes in the
/// `BLOCKED-*` log line so an operator can `linprov allow <token>`.
#[allow(clippy::too_many_arguments)]
fn record_block_token(
    blocks: &mut BlocksTable,
    event: &Event,
    target: &str,
    landing_folder: &Option<String>,
    landing_basename: &Option<String>,
    creator_path: &Option<String>,
    creator_comm: &str,
) -> String {
    let exec_uid = get_uid_for_pid(event.pid).unwrap_or(0);
    let ctx = OriginContext {
        target_filename: target,
        landing_folder: landing_folder.as_deref(),
        landing_basename: landing_basename.as_deref(),
        creator_path: creator_path.as_deref(),
        creator_comm,
        creator_uid: event.origin.creator_uid,
        execution_uid: exec_uid,
    };
    blocks.record(rule_from_context(&ctx, ALLOW_DIMS).to_line())
}

/// In soak mode, emit one allowlist rule for this event keyed on `target`
/// (the live exec path for execve, the script path for script-exec) plus
/// the record-resolved landing/creator dims. Shared by `on_execve_marked`
/// and `on_script_exec`.
#[allow(clippy::too_many_arguments)]
fn maybe_soak(
    cfg: &Config,
    event: &Event,
    target: &str,
    landing_folder: &Option<String>,
    landing_basename: &Option<String>,
    creator_path: &Option<String>,
    creator_comm: &str,
) {
    if cfg.mode != ModeArg::Soak {
        return;
    }
    let Some(soak) = cfg.soak.as_ref() else {
        return;
    };
    let exec_uid = get_uid_for_pid(event.pid).unwrap_or(0);
    let ctx = OriginContext {
        target_filename: target,
        landing_folder: landing_folder.as_deref(),
        landing_basename: landing_basename.as_deref(),
        creator_path: creator_path.as_deref(),
        creator_comm,
        creator_uid: event.origin.creator_uid,
        execution_uid: exec_uid,
    };
    match soak.record(&ctx) {
        Ok(Some(line)) => info!("soak: added `{line}`"),
        Ok(None) => {}
        Err(e) => warn!("soak append failed: {e}"),
    }
}

fn get_uid_for_pid(pid: u32) -> Option<u32> {
    let s = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Uid: <real> <effective> <saved> <fs>
            let real = rest.split_whitespace().next()?;
            return real.parse().ok();
        }
    }
    None
}

/// Render a db-resolved value, or the raw hash if it couldn't be
/// resolved (so logs stay actionable: `grep <hash> hashes.tsv`).
fn resolved(s: &Option<String>, hash: u64) -> String {
    match s {
        Some(v) => v.clone(),
        None if hash == 0 => "<none>".to_string(),
        None => format!("<hash:{hash:016x}>"),
    }
}

fn format_origin(o: &OriginRecord, creator_comm: &str, creator_path: &Option<String>) -> String {
    format!(
        "{{v:{},ts_boot_ns:{},pid:{},uid:{},comm:{},creator:{}}}",
        o.version,
        o.ts_boot_ns,
        o.pid,
        o.creator_uid,
        creator_comm,
        resolved(creator_path, o.creator_path_hash),
    )
}

fn comm_to_string(comm: &[u8; COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn c_str_to_string(buf: &[u8; EXEC_PATH_LEN]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Final path component (basename), no slash. `None` for empty input or
/// a trailing-slash path (which has no basename).
fn basename_of(path: &str) -> Option<&str> {
    let base = path.rsplit_once('/').map(|(_, b)| b).unwrap_or(path);
    if base.is_empty() {
        None
    } else {
        Some(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_split() {
        assert_eq!(basename_of("/a/b/foo.sh"), Some("foo.sh"));
        assert_eq!(basename_of("/foo"), Some("foo"));
        assert_eq!(basename_of("/a/b/"), None);
    }

    #[test]
    fn ancestor_prefixes_shallow_to_deep() {
        // The byte loop in on_file_marked produces these `/`-prefixes.
        let path = "/a/b/c/foo";
        let prefixes: Vec<&str> = path
            .bytes()
            .enumerate()
            .filter(|(_, b)| *b == b'/')
            .map(|(i, _)| &path[..=i])
            .collect();
        assert_eq!(prefixes, vec!["/", "/a/", "/a/b/", "/a/b/c/"]);
    }
}

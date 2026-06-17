//! Quarantine: neutralize a blocked file instead of allowing it.
//!
//! Where `linprov allow` *permits* a blocked exec, quarantine does the
//! opposite — it moves the file into a root-only store (0700) and drops a
//! restore manifest so `linprov quarantine restore <id>` can put it back
//! later. Moving it out of every allowed location breaks any path/folder
//! allow rule, and the stored body is left mode `0000`, so it can no longer
//! be exec'd *or* read by an interpreter.
//!
//! Two entry points, by design split on trust:
//!   * **stash** is daemon-side, reached over the group-writable control
//!     socket (`quarantine <token>`). The client sends only the token; the
//!     daemon resolves the path *it* recorded at block time — a caller can
//!     never name an arbitrary file for root to move. A `dev`/`ino` recheck
//!     (plus `O_NOFOLLOW`) refuses a file swapped since it was blocked.
//!   * **list / restore** are direct root CLI ops on the on-disk manifests.
//!     They need no live daemon state, so they work even with the daemon
//!     down, and keep a second privileged verb off the shared socket.

use std::{
    ffi::{CStr, CString},
    fs::{self, File},
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::{config::DEFAULT_CONTROL_SOCKET_PATH, config::DEFAULT_QUARANTINE_DIR, privilege};

/// Subdirectory under the quarantine root that holds the file bodies and
/// their `<id>.toml` manifests. Keeping bodies in a child dir leaves room
/// for sibling state later without colliding with `<id>` names.
const STORE_SUBDIR: &str = "store";

/// Restore record written next to each quarantined body as `<id>.toml`.
/// Plaintext on purpose (consistent with the hash-db audit file) so an
/// operator can read or hand-edit it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// `<token>-<unix-secs>` — the body filename and the restore handle.
    pub id: String,
    /// The block token this file was quarantined under.
    pub token: String,
    /// Absolute path the file was moved from (where restore puts it back).
    pub original_path: String,
    pub uid: u32,
    pub gid: u32,
    /// Full `st_mode` as captured; restore masks to the permission bits.
    pub mode: u32,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub size: u64,
    /// `dev`/`ino` recorded at block time, re-verified before the move.
    pub dev: u64,
    pub ino: u64,
    /// Origin (mark-of-the-web) xattr bytes as lowercase hex, if the file
    /// still carried one — restored verbatim so provenance survives.
    #[serde(default)]
    pub origin_hex: Option<String>,
    pub quarantined_at: u64,
}

/// Outcome of a successful [`stash`], for the daemon's `OK` reply.
pub struct Stashed {
    pub id: String,
    pub original_path: String,
}

/// Prefix the daemon puts on the `ERR` reply for a tamper-suspected
/// quarantine failure, so the tray (and `quarantine apply`) can escalate the
/// alert instead of treating it like an ordinary rejection. Part of the
/// control-socket wire contract.
pub const TAMPER_MARKER: &str = "possible-tamper";

/// A [`stash`] failure, tagged with whether it looks like *tampering* — the
/// recorded file was swapped, redirected through a symlink, or turned into a
/// non-regular file between the block and the move. That's the signature of
/// someone racing quarantine to keep a blocked file in place, so it warrants
/// a loud, persistent alert; ordinary failures (expired token, IO error, a
/// file that's simply gone) do not.
pub struct StashError {
    pub tamper: bool,
    pub source: anyhow::Error,
}

impl StashError {
    fn tamper(source: anyhow::Error) -> Self {
        Self {
            tamper: true,
            source,
        }
    }
    fn plain(source: anyhow::Error) -> Self {
        Self {
            tamper: false,
            source,
        }
    }
}

/// Move the blocked file `target` into the quarantine store under `dir`,
/// writing a restore manifest. `want_dev`/`want_ino` are what the daemon
/// recorded at block time; a mismatch (file replaced since) aborts the move.
///
/// Daemon-side only — `target` is the path the daemon itself recorded, never
/// a client-supplied one.
pub fn stash(
    token: &str,
    target: &str,
    want_dev: u64,
    want_ino: u64,
    dir: &Path,
) -> Result<Stashed, StashError> {
    let target_path = Path::new(target);
    let parent = target_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| StashError::plain(anyhow!("`{target}` has no parent directory")))?;
    let basename = target_path
        .file_name()
        .ok_or_else(|| StashError::plain(anyhow!("`{target}` has no final path component")))?;
    let basename_c = CString::new(basename.as_bytes())
        .map_err(|_| StashError::plain(anyhow!("`{target}` basename has an interior NUL")))?;

    // 1. Resolve the parent directory WITHOUT following any symlink in the
    //    path (openat2 + RESOLVE_NO_SYMLINKS). This is the crux of the
    //    hardening: a recorded path's parents are often attacker-writable
    //    (downloads live in user dirs), so a plain open could be redirected
    //    by swapping a parent component for a symlink — handing this
    //    root-privileged move a victim path like /etc. A symlink anywhere in
    //    the path now fails (ELOOP) instead, which we treat as tamper.
    let parent_fd = open_dir_no_symlinks(parent)
        .map_err(|e| classify_path_error(target, e, "resolving the parent directory of"))?;

    // 2. Open the file itself relative to the verified parent, never following
    //    a final-component symlink. Everything downstream acts through this fd
    //    or the parent fd — never a re-resolved absolute path.
    let file_fd = openat_nofollow(parent_fd.as_raw_fd(), &basename_c)
        .map_err(|e| classify_path_error(target, e, "opening the blocked file"))?;

    // 3. Verify identity on the held descriptor.
    let st = fstat(file_fd.as_raw_fd()).map_err(|e| {
        StashError::plain(anyhow::Error::from(e).context("stat-ing the blocked file"))
    })?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(StashError::tamper(anyhow!(
            "`{target}` is no longer a regular file — it was replaced since it was blocked"
        )));
    }
    let (dev, ino) = stat_ids(&st);
    if dev != want_dev || ino != want_ino {
        return Err(StashError::tamper(anyhow!(
            "`{target}` changed since it was blocked (dev/ino mismatch) — a different file now sits at that path"
        )));
    }

    // Past the tamper checks: the remaining work is plain IO, so any failure
    // is an ordinary (non-tamper) error.
    finish_stash(
        token,
        target,
        want_dev,
        want_ino,
        dir,
        &parent_fd,
        &basename_c,
        file_fd,
        &st,
    )
    .map_err(StashError::plain)
}

/// The IO tail of [`stash`], after the identity checks pass: read the origin
/// mark off the verified fd, move the file into the store (anchored to the
/// verified directory fds, so it can't be redirected), neutralize it, and
/// write the manifest.
#[allow(clippy::too_many_arguments)]
fn finish_stash(
    token: &str,
    target: &str,
    want_dev: u64,
    want_ino: u64,
    dir: &Path,
    parent_fd: &OwnedFd,
    basename_c: &CStr,
    file_fd: OwnedFd,
    st: &libc::stat,
) -> Result<Stashed> {
    // Read the origin mark off the verified fd, not a re-resolved path.
    let origin = fgetxattr(file_fd.as_raw_fd(), linprov_common::XATTR_NAME)
        .ok()
        .flatten();
    let origin_hex = origin.as_deref().map(hex_encode);

    let store = dir.join(STORE_SUBDIR);
    fs::create_dir_all(&store)
        .with_context(|| format!("creating quarantine store `{}`", store.display()))?;
    // Root-only, both the root and the store dir.
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    let _ = fs::set_permissions(&store, fs::Permissions::from_mode(0o700));
    // The store lives under a root-owned tree, so a plain open is safe here;
    // we just need its fd to anchor the destination side of the move.
    let store_dir = File::open(&store)
        .with_context(|| format!("opening quarantine store `{}`", store.display()))?;
    let store_fd = store_dir.as_raw_fd();

    let ts = unix_secs();
    let id = format!("{token}-{ts}");
    let id_c = CString::new(id.as_str()).context("quarantine id has an interior NUL")?;

    // Move, anchored to the verified directory fds. `renameat`/`unlinkat`
    // relative to `parent_fd` can't be redirected by a swapped parent symlink.
    // SAFETY: both fds are live; both names are NUL-terminated.
    let rc = unsafe {
        libc::renameat(
            parent_fd.as_raw_fd(),
            basename_c.as_ptr(),
            store_fd,
            id_c.as_ptr(),
        )
    };
    if rc == 0 {
        // Same-filesystem rename done. Neutralize the stored body in place.
        // SAFETY: `store_fd` live, `id_c` NUL-terminated.
        unsafe { libc::fchmodat(store_fd, id_c.as_ptr(), 0o000, 0) };
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EXDEV) {
            return Err(
                anyhow::Error::from(err).context(format!("moving `{target}` into quarantine"))
            );
        }
        // Cross-filesystem: copy from the *verified fd* (so the bytes are the
        // file we checked, whatever later happens to the path), fsync, then
        // remove the original only if it still has the verified identity.
        let mut out = openat_create(store_fd, &id_c, 0o600)
            .with_context(|| format!("creating quarantine body for `{target}`"))?;
        let mut src = File::from(file_fd);
        io::copy(&mut src, &mut out)
            .with_context(|| format!("copying `{target}` across filesystems into quarantine"))?;
        out.sync_all().context("fsync quarantine body")?;
        if let Some(bytes) = &origin {
            let _ = fsetxattr(out.as_raw_fd(), linprov_common::XATTR_NAME, bytes);
        }
        // SAFETY: `out` is a live fd.
        unsafe { libc::fchmod(out.as_raw_fd(), 0o000) };
        // Remove the original relative to the verified parent fd — but only if
        // it still matches the inode we stored, so a file swapped in since
        // isn't the one we unlink.
        match fstatat_nofollow(parent_fd.as_raw_fd(), basename_c) {
            Ok(now) if stat_ids(&now) == (want_dev, want_ino) => {
                // SAFETY: `parent_fd` live, `basename_c` NUL-terminated.
                if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), basename_c.as_ptr(), 0) } != 0 {
                    let e = io::Error::last_os_error();
                    warn!("quarantined `{target}` (copied) but could not remove the original: {e}");
                }
            }
            _ => warn!(
                "quarantined `{target}` (copied) but left the original in place: it \
                 changed before removal (possible concurrent swap)"
            ),
        }
    }

    // The libc::stat field widths vary by platform; the casts are no-ops on
    // x86_64 but keep this correct elsewhere.
    #[allow(clippy::unnecessary_cast)]
    let manifest = Manifest {
        id: id.clone(),
        token: token.to_string(),
        original_path: target.to_string(),
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode as u32,
        mtime: st.st_mtime as i64,
        mtime_nsec: st.st_mtime_nsec as i64,
        size: st.st_size as u64,
        dev: want_dev,
        ino: want_ino,
        origin_hex,
        quarantined_at: ts,
    };
    write_manifest(&store, &manifest)?;

    Ok(Stashed {
        id,
        original_path: target.to_string(),
    })
}

/// All quarantine manifests under `dir`, oldest first. A missing store is an
/// empty list, not an error.
pub fn list(dir: &Path) -> Result<Vec<Manifest>> {
    let store = dir.join(STORE_SUBDIR);
    let rd = match fs::read_dir(&store) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading `{}`", store.display())),
    };
    let mut out = Vec::new();
    for ent in rd {
        let path = ent?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        match fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|s| toml::from_str::<Manifest>(&s).map_err(anyhow::Error::from))
        {
            Ok(m) => out.push(m),
            Err(e) => warn!("skipping unreadable manifest `{}`: {e:#}", path.display()),
        }
    }
    out.sort_by_key(|m| m.quarantined_at);
    Ok(out)
}

/// Restore the quarantined entry `id` to its original path, re-applying the
/// recorded owner, mode, mtime, and origin xattr. If a file has reappeared
/// at the original path, restore beside it as `<path>.restored.<id>` rather
/// than clobber it. Returns the path actually written.
pub fn restore(dir: &Path, id: &str) -> Result<String> {
    let store = dir.join(STORE_SUBDIR);
    let manifest_path = store.join(format!("{id}.toml"));
    let body = store.join(id);

    let s = fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading manifest for `{id}` (no such quarantine entry?)"))?;
    let m: Manifest = toml::from_str(&s).context("parsing quarantine manifest")?;
    if !body.exists() {
        bail!(
            "quarantine body for `{id}` is missing at {}",
            body.display()
        );
    }

    let mut dest = PathBuf::from(&m.original_path);
    if dest.symlink_metadata().is_ok() {
        let alt = PathBuf::from(format!("{}.restored.{id}", m.original_path));
        warn!(
            "`{}` already exists; restoring beside it as `{}`",
            m.original_path,
            alt.display()
        );
        dest = alt;
    }
    if let Some(parent) = dest.parent() {
        let _ = fs::create_dir_all(parent);
    }

    match fs::rename(&body, &dest) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            fs::copy(&body, &dest)
                .with_context(|| format!("copying `{id}` back to `{}`", dest.display()))?;
            fs::remove_file(&body).ok();
        }
        Err(e) => {
            return Err(e).with_context(|| format!("restoring `{id}` to `{}`", dest.display()))
        }
    }

    let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(m.mode & 0o7777));
    chown(&dest, m.uid, m.gid).with_context(|| {
        format!(
            "restoring owner {}:{} on `{}`",
            m.uid,
            m.gid,
            dest.display()
        )
    })?;
    let _ = set_mtime(&dest, m.mtime, m.mtime_nsec);
    if let Some(hex) = &m.origin_hex {
        if let Some(bytes) = hex_decode(hex) {
            // No-follow: the restore dest may sit in a user-writable dir, so a
            // symlink swapped in at that path mustn't redirect this write.
            let _ = set_xattr_no_follow(&dest, linprov_common::XATTR_NAME, &bytes);
        }
    }
    let _ = fs::remove_file(&manifest_path);

    Ok(dest.to_string_lossy().into_owned())
}

// --- CLI: `linprov quarantine {apply|list|restore}` ------------------------

#[derive(Parser, Debug)]
pub struct QuarantineArgs {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Quarantine a blocked file by the token from its `BLOCKED-*` log line
    /// (asks the running daemon over the control socket).
    Apply {
        /// Token from the `[allow: <token>]` suffix of a `BLOCKED-*` line.
        token: String,
        /// Daemon control socket to connect to.
        #[arg(long, default_value = DEFAULT_CONTROL_SOCKET_PATH)]
        socket: PathBuf,
    },
    /// List quarantined files and their restore ids.
    List {
        /// Quarantine store root.
        #[arg(long, default_value = DEFAULT_QUARANTINE_DIR)]
        dir: PathBuf,
    },
    /// Restore a quarantined file to its original path by id.
    Restore {
        /// Restore id (the `id` column from `quarantine list`).
        id: String,
        /// Quarantine store root.
        #[arg(long, default_value = DEFAULT_QUARANTINE_DIR)]
        dir: PathBuf,
    },
}

pub fn run(args: QuarantineArgs) -> Result<()> {
    match args.cmd {
        Cmd::Apply { token, socket } => apply_via_daemon(&socket, &token),
        Cmd::List { dir } => {
            privilege::require_root("listing quarantined files")?;
            print_list(&dir)
        }
        Cmd::Restore { id, dir } => {
            privilege::require_root("restoring a quarantined file")?;
            let path = restore(&dir, &id)?;
            println!("restored to {path}");
            Ok(())
        }
    }
}

/// Send `quarantine <token>` to the daemon (mirrors `linprov allow`).
fn apply_via_daemon(socket: &Path, token: &str) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "connecting to the linprov control socket at {} \
             (is the daemon running? are you root or in the linprov group?)",
            socket.display()
        )
    })?;
    stream
        .write_all(format!("quarantine {token}\n").as_bytes())
        .context("sending request")?;
    stream.shutdown(Shutdown::Write).ok();
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .context("reading reply from daemon")?;
    let reply = reply.trim();
    if let Some(detail) = reply.strip_prefix("OK ") {
        println!("{detail}");
        Ok(())
    } else if let Some(msg) = reply.strip_prefix("ERR ") {
        if let Some(detail) = msg.strip_prefix(TAMPER_MARKER) {
            Err(anyhow!(
                "POSSIBLE TAMPER — the file changed since it was blocked; \
                 someone may be racing quarantine to keep it in place:{detail}"
            ))
        } else {
            Err(anyhow!("daemon rejected the request: {msg}"))
        }
    } else {
        Err(anyhow!("unexpected reply from daemon: {reply:?}"))
    }
}

fn print_list(dir: &Path) -> Result<()> {
    let entries = list(dir)?;
    if entries.is_empty() {
        println!("no quarantined files under {}", dir.display());
        return Ok(());
    }
    println!("{:<28}  ORIGINAL PATH", "ID");
    for m in entries {
        println!("{:<28}  {}", m.id, m.original_path);
    }
    Ok(())
}

// --- small unix helpers ----------------------------------------------------

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map a path-resolution/open error to a [`StashError`], flagging symlink
/// interposition (`ELOOP`) as suspected tamper. A file that's simply gone
/// (`ENOENT`) or any other IO error is ordinary, not an alarm.
fn classify_path_error(target: &str, e: io::Error, what: &str) -> StashError {
    if e.raw_os_error() == Some(libc::ELOOP) {
        StashError::tamper(anyhow!(
            "`{target}` is now reached through a symlink — a path component was \
             replaced since it was blocked"
        ))
    } else {
        StashError::plain(anyhow::Error::from(e).context(format!("{what} `{target}`")))
    }
}

/// Open `path` as a directory fd, refusing to traverse ANY symlink in the
/// path (`openat2` + `RESOLVE_NO_SYMLINKS`). The returned `O_PATH` fd is
/// usable as the `dirfd` of subsequent `*at` calls.
fn open_dir_no_symlinks(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // `open_how` is `#[non_exhaustive]`, so build it zeroed and set fields.
    // SAFETY: an all-zero `open_how` is a valid (no-op) request.
    let mut how: libc::open_how = unsafe { mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: `c` is a valid NUL-terminated path and `how` is a correctly
    // sized `open_how` live for the duration of the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            &how as *const libc::open_how,
            mem::size_of::<libc::open_how>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat2` returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// `openat` of `name` under `dirfd`, read-only, never following a
/// final-component symlink.
fn openat_nofollow(dirfd: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `dirfd` is a live directory fd; `name` is NUL-terminated.
    let ret = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(ret) })
}

/// Create `name` under `dirfd` (`O_CREAT|O_EXCL`), returning it as a `File`.
fn openat_create(dirfd: RawFd, name: &CStr, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: `dirfd` live, `name` NUL-terminated; `mode` is the variadic arg.
    let ret = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh owned fd.
    Ok(unsafe { File::from_raw_fd(ret) })
}

/// `(dev, ino)` as fixed-width `u64`s — the cast is a no-op on x86_64 but
/// keeps the comparison correct where `dev_t`/`ino_t` are narrower.
#[allow(clippy::unnecessary_cast)]
fn stat_ids(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: a zeroed `stat` is valid to fill; `fd` is live.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn fstatat_nofollow(dirfd: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: zeroed `stat`; `dirfd` live; `name` NUL-terminated.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// Read extended attribute `name` off an open fd. `None` if it's absent.
fn fgetxattr(fd: RawFd, name: &str) -> io::Result<Option<Vec<u8>>> {
    let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: a null buffer with size 0 is the documented size-query idiom.
    let len = unsafe { libc::fgetxattr(fd, cname.as_ptr(), ptr::null_mut(), 0) };
    if len < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(e);
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` has room for `len` bytes; `fd` live.
    let got = unsafe {
        libc::fgetxattr(
            fd,
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(Some(buf))
}

/// Write extended attribute `name` on an open fd.
fn fsetxattr(fd: RawFd, name: &str, value: &[u8]) -> io::Result<()> {
    let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `value` is valid for `value.len()` bytes; `fd` live.
    let rc = unsafe {
        libc::fsetxattr(
            fd,
            cname.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set extended attribute `name` on `path` WITHOUT following a final-component
/// symlink (`lsetxattr`). Used by [`restore`] on the just-written destination;
/// the no-follow keeps a symlink swapped into the restore path from
/// redirecting this write. (main dropped the `xattr` crate in favor of raw
/// libc calls like this one — see handler.rs.)
fn set_xattr_no_follow(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: both C strings are valid + NUL-terminated for the call; `value`
    // is valid for `value.len()` bytes.
    let rc = unsafe {
        libc::lsetxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn write_manifest(store: &Path, m: &Manifest) -> Result<()> {
    let path = store.join(format!("{}.toml", m.id));
    let body = toml::to_string(m).context("serializing quarantine manifest")?;
    fs::write(&path, body).with_context(|| format!("writing manifest `{}`", path.display()))?;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    Ok(())
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c =
        CString::new(path.as_os_str().as_encoded_bytes()).context("path has an interior NUL")?;
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error()).context("chown");
    }
    Ok(())
}

fn set_mtime(path: &Path, secs: i64, nsec: i64) -> Result<()> {
    let c =
        CString::new(path.as_os_str().as_encoded_bytes()).context("path has an interior NUL")?;
    let times = [
        // atime: leave as-is.
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: secs as libc::time_t,
            tv_nsec: nsec as _,
        },
    ];
    // SAFETY: `c` is a valid path; `times` is a 2-element timespec array.
    if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error()).context("utimensat");
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00u8, 0x04, 0xfe, 0xff, 0x7f, 0x80];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "0004feff7f80");
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_odd_and_nonhex() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn manifest_toml_round_trip() {
        let m = Manifest {
            id: "deadbeef-123".to_string(),
            token: "deadbeef".to_string(),
            original_path: "/home/u/Downloads/x".to_string(),
            uid: 1000,
            gid: 1000,
            mode: 0o100755,
            mtime: 1_700_000_000,
            mtime_nsec: 42,
            size: 9,
            dev: 66306,
            ino: 12345,
            origin_hex: Some("0102".to_string()),
            quarantined_at: 1_700_000_500,
        };
        let s = toml::to_string(&m).unwrap();
        let back: Manifest = toml::from_str(&s).unwrap();
        assert_eq!(back.id, m.id);
        assert_eq!(back.original_path, m.original_path);
        assert_eq!(back.mode, m.mode);
        assert_eq!(back.origin_hex, m.origin_hex);
    }
}

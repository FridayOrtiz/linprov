//! Copy the running binary to `/usr/local/bin/linprov`.
//!
//! `cargo install linprov` drops the binary in `~/.cargo/bin/`, which
//! isn't on root's `secure_path`. So `sudo linprov ...` fails with
//! `command not found` until we put a copy in a system-wide spot.
//! `setup` and `upgrade` both call into here.

use std::{
    env,
    ffi::{CStr, CString},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Context, Result};
use log::info;

/// Outcome of `install_to`. Lets callers decide what to print.
pub enum Outcome {
    /// We just wrote `dest`; this is the first time, or it differed.
    Installed,
    /// `src` *is* `dest` (already running from the install path) or
    /// the bytes already matched. Nothing changed.
    AlreadyCurrent,
}

/// Copy `src` to `dest`, mode 0755. Idempotent: skips the copy when
/// the destination already has matching bytes. Won't follow `dest` if
/// it's a symlink — it'll be replaced atomically via tmp-and-rename so
/// a daemon currently executing the old `dest` keeps running on its
/// existing mmap.
pub fn install_to(src: &Path, dest: &Path) -> Result<Outcome> {
    let src = canonical(src)?;
    if dest_matches_running(&src, dest) {
        return Ok(Outcome::AlreadyCurrent);
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating `{}`", parent.display()))?;
    }
    // Write to a sibling tmp file, chmod, then rename. atomic on the
    // same filesystem; safe to do even if the old `dest` is mapped by
    // a running process.
    let tmp = dest.with_extension("linprov-new");
    fs::copy(&src, &tmp)
        .with_context(|| format!("copying `{}` -> `{}`", src.display(), tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 `{}`", tmp.display()))?;
    fs::rename(&tmp, dest)
        .with_context(|| format!("renaming `{}` -> `{}`", tmp.display(), dest.display()))?;
    info!("installed {} -> {}", src.display(), dest.display());
    Ok(Outcome::Installed)
}

fn canonical(p: &Path) -> Result<PathBuf> {
    p.canonicalize()
        .with_context(|| format!("resolving `{}`", p.display()))
}

fn dest_matches_running(src: &Path, dest: &Path) -> bool {
    let Ok(src_meta) = fs::metadata(src) else {
        return false;
    };
    let Ok(dest_meta) = fs::metadata(dest) else {
        return false;
    };
    src_meta.len() == dest_meta.len() && fs::read(src).ok() == fs::read(dest).ok()
}

/// Path to the currently-running binary. Wraps `env::current_exe`
/// with a useful error.
pub fn current_exe() -> Result<PathBuf> {
    std::env::current_exe().context("locating the running linprov binary")
}

/// Best-effort: find the freshly `cargo install`-ed binary in
/// somebody's `~/.cargo/bin/linprov`.
///
/// `linprov upgrade` typically runs under elevated privileges
/// (`sudo`, `doas`, `pkexec`, `su -`, or just logged in as root),
/// while the binary the user just installed lives in their *user*
/// home. We try a chain of heuristics to find that home, in order
/// of decreasing confidence — but only ever ones that tie back to a
/// *confirmed invoker* or root, since the result is copied over the
/// system binary and run as root:
///   1. `$SUDO_USER` / `$DOAS_USER` env vars
///   2. `$PKEXEC_UID` → username
///   3. `logname(1)` — reads the controlling terminal's login user
///      (works for `su` regardless of `-`)
///   4. The effective UID's own home dir — covers the "root logged
///      in directly and `cargo install`-ed as root" case
///
/// We deliberately do NOT scan arbitrary `/etc/passwd` homes for a
/// `~/.cargo/bin/linprov`: a root-context upgrade (cron, root shell)
/// with no confirmed invoker would then copy and run some unrelated
/// local user's binary as root — a local privilege-escalation. The
/// resolved path is still re-checked by [`ensure_trusted_source`]
/// before install.
///
/// Returns `None` if every candidate path is missing. Callers should
/// fall through to a `--source <path>` override or surface a hard
/// error.
pub fn cargo_install_source() -> Option<PathBuf> {
    for user in candidate_users() {
        if let Some(p) = cargo_bin_for_user(&user) {
            return Some(p);
        }
    }
    // EUID's own home — typically `/root/.cargo/bin/linprov` for the
    // "su then cargo install then upgrade" flow.
    let euid = unsafe { libc::geteuid() };
    if let Some(home) = home_dir_for_uid(euid) {
        let p = home.join(".cargo").join("bin").join("linprov");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Refuse an upgrade source an untrusted party could have written.
///
/// The resolved binary is about to be copied over the system install path
/// and run as root, so it must not be attacker-controlled. We require:
///   * a regular file (after following symlinks),
///   * not group- or world-writable (`mode & 0o022 == 0`), and
///   * for an auto-detected source, owned by root or by a *confirmed*
///     invoker (`$SUDO_USER` / `$DOAS_USER` / `$PKEXEC_UID` / `logname`, or
///     the effective uid).
///
/// `explicit` (a `--source` the operator named) trusts the chosen owner but
/// still must clear the regular-file + not-writable checks. Without this, a
/// root-context `linprov upgrade` that auto-detected a non-root user's
/// `~/.cargo/bin/linprov` would copy and run that user's binary as root.
pub fn ensure_trusted_source(source: &Path, explicit: bool) -> Result<()> {
    let meta = fs::metadata(source)
        .with_context(|| format!("stat-ing upgrade source `{}`", source.display()))?;
    if !meta.is_file() {
        return Err(anyhow!(
            "upgrade source `{}` is not a regular file; refusing to install it",
            source.display()
        ));
    }
    let mode = meta.mode();
    if mode & 0o022 != 0 {
        return Err(anyhow!(
            "upgrade source `{}` is group- or world-writable (mode {:o}); refusing \
             to install a binary an untrusted user could have modified. Fix its \
             permissions or pass a trusted --source.",
            source.display(),
            mode & 0o7777,
        ));
    }
    if explicit {
        return Ok(()); // operator named it; its owner is their call
    }
    let owner = meta.uid();
    if owner == 0 || trusted_owner_uids().contains(&owner) {
        return Ok(());
    }
    Err(anyhow!(
        "auto-detected upgrade source `{}` is owned by uid {owner}, who isn't root \
         or the user who invoked this command — refusing to copy and run it as \
         root. Re-run as the intended user (so $SUDO_USER is set) or pass an \
         explicit --source you trust.",
        source.display(),
    ))
}

/// UIDs whose files we trust as an auto-detected upgrade source: root, the
/// effective uid, and any confirmed invoker behind sudo/doas/pkexec/su.
fn trusted_owner_uids() -> Vec<u32> {
    let mut uids = vec![0u32, unsafe { libc::geteuid() } as u32];
    for user in candidate_users() {
        if let Some(u) = lookup_user(&user) {
            uids.push(u.uid);
        }
    }
    uids
}

/// The real (non-root) user behind `sudo`/`doas`/`pkexec`/`su`, with
/// name + uid + primary gid + home resolved in one `getpwnam` pass.
/// `None` if we can't pin down a non-root invoker (genuinely running as
/// root with no `$SUDO_USER`, etc.). `setup` uses this to wire up the
/// per-user tray agent (`usermod`, `~/.config/systemd/user`, dropping to
/// the user for `systemctl --user`).
pub struct InvokingUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

pub fn invoking_user() -> Option<InvokingUser> {
    candidate_users().into_iter().find_map(|u| lookup_user(&u))
}

/// Resolve a username to its full passwd row (uid/gid/home).
fn lookup_user(name: &str) -> Option<InvokingUser> {
    let cname = CString::new(name).ok()?;
    // SAFETY: `getpwnam` returns a pointer to a static buffer; we copy
    // every field out before returning, and callers are single-threaded.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    let uid = unsafe { (*pw).pw_uid } as u32;
    let gid = unsafe { (*pw).pw_gid } as u32;
    let home = pw_home(pw)?;
    Some(InvokingUser {
        name: name.to_string(),
        uid,
        gid,
        home,
    })
}

/// Username candidates from env vars + `logname`. Skips "root" since
/// we want the *invoker*, not the elevated identity.
fn candidate_users() -> Vec<String> {
    let mut v = Vec::new();
    let mut push = |s: String| {
        if !s.is_empty() && s != "root" && !v.contains(&s) {
            v.push(s);
        }
    };
    if let Ok(u) = env::var("SUDO_USER") {
        push(u);
    }
    if let Ok(u) = env::var("DOAS_USER") {
        push(u);
    }
    if let Ok(uid_str) = env::var("PKEXEC_UID") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            if let Some(u) = username_for_uid(uid) {
                push(u);
            }
        }
    }
    if let Some(u) = run_logname() {
        push(u);
    }
    v
}

fn cargo_bin_for_user(user: &str) -> Option<PathBuf> {
    let home = home_dir_for(user)?;
    let p = home.join(".cargo").join("bin").join("linprov");
    p.exists().then_some(p)
}

/// `logname(1)` resolves the login user from the controlling
/// terminal's utmp entry. Survives `su` (with or without `-`), fails
/// gracefully when there's no controlling tty.
fn run_logname() -> Option<String> {
    let out = Command::new("/usr/bin/logname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// `getpwnam`-based home dir lookup. Single-threaded callers only.
fn home_dir_for(user: &str) -> Option<PathBuf> {
    let cname = CString::new(user).ok()?;
    // SAFETY: `getpwnam` returns a pointer to a static buffer; we
    // copy the home-dir string before returning, and linprov is
    // single-threaded at this point in `upgrade::run`, so no other
    // thread can race with us through the static buffer.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    pw_home(pw)
}

fn home_dir_for_uid(uid: libc::uid_t) -> Option<PathBuf> {
    // SAFETY: same caveats as `getpwnam` above.
    let pw = unsafe { libc::getpwuid(uid) };
    pw_home(pw)
}

fn username_for_uid(uid: u32) -> Option<String> {
    // SAFETY: same caveats as `getpwnam` above.
    let pw = unsafe { libc::getpwuid(uid as libc::uid_t) };
    if pw.is_null() {
        return None;
    }
    let n = unsafe { (*pw).pw_name };
    if n.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(n) };
    cstr.to_str().ok().map(String::from)
}

fn pw_home(pw: *mut libc::passwd) -> Option<PathBuf> {
    if pw.is_null() {
        return None;
    }
    let dir = unsafe { (*pw).pw_dir };
    if dir.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(dir) };
    Some(PathBuf::from(cstr.to_str().ok()?))
}

/// Refuse to install over a binary that's owned by the distro package
/// manager (dpkg/rpm/pacman). Belt and suspenders — `/usr/local/bin`
/// is conventionally off-limits to distro packages, so the common case
/// is the check passes trivially.
pub fn refuse_distro_owned(dest: &Path) -> Result<()> {
    if !dest.exists() {
        return Ok(());
    }
    // (tool, query args, human name). Each exits 0 and prints the owning
    // package when `dest` is package-managed: `dpkg -S`, `rpm -qf`,
    // `pacman -Qo`. Whichever tool the host has runs; a missing one (spawn
    // error) is simply skipped, so this works across Debian/Fedora/Arch.
    let probes: &[(&str, &[&str], &str)] = &[
        ("/usr/bin/dpkg", &["-S"], "dpkg"),
        ("/usr/bin/rpm", &["-qf"], "rpm"),
        ("/usr/bin/pacman", &["-Qo"], "pacman"),
    ];
    for (tool, args, name) in probes {
        let out = match Command::new(tool).args(*args).arg(dest).output() {
            Ok(o) => o,
            Err(_) => continue, // tool not installed on this distro
        };
        if out.status.success() {
            let pkg = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Err(anyhow!(
                "{} is owned by a {name} package ({pkg}); refusing to overwrite. \
                 Uninstall that package first.",
                dest.display()
            ));
        }
    }
    Ok(())
}

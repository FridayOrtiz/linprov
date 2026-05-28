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
    os::unix::fs::PermissionsExt,
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
/// of decreasing confidence:
///   1. `$SUDO_USER` / `$DOAS_USER` env vars
///   2. `$PKEXEC_UID` → username
///   3. `logname(1)` — reads the controlling terminal's login user
///      (works for `su` regardless of `-`)
///   4. The effective UID's own home dir — covers the "root logged
///      in directly and `cargo install`-ed as root" case
///   5. Scanning /etc/passwd for human users (UID 1000–65533) with
///      `~/.cargo/bin/linprov`; only matches if there's *exactly
///      one*, otherwise we'd guess wrong on multi-user hosts
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
    scan_human_homes_for_cargo_bin()
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

/// Last-resort scan: walk /etc/passwd, find human users (UID
/// 1000–65533) with a `~/.cargo/bin/linprov`, return the path *only
/// if there's exactly one candidate*. Multiple matches → bail, since
/// we'd be guessing whose binary the user actually wants.
fn scan_human_homes_for_cargo_bin() -> Option<PathBuf> {
    let content = fs::read_to_string("/etc/passwd").ok()?;
    let candidates: Vec<PathBuf> = content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 6 {
                return None;
            }
            let uid: u32 = parts[2].parse().ok()?;
            if !(1000..65534).contains(&uid) {
                return None;
            }
            let p = PathBuf::from(parts[5]).join(".cargo/bin/linprov");
            p.exists().then_some(p)
        })
        .collect();
    if candidates.len() == 1 {
        candidates.into_iter().next()
    } else {
        None
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
/// manager (apt/dnf/pacman). Belt and suspenders — `/usr/local/bin`
/// is conventionally off-limits to distro packages, so the common case
/// is the check passes trivially.
pub fn refuse_distro_owned(dest: &Path) -> Result<()> {
    if !dest.exists() {
        return Ok(());
    }
    // dpkg: `dpkg -S /path` exits 0 with the owning package name.
    if let Ok(out) = Command::new("/usr/bin/dpkg").arg("-S").arg(dest).output() {
        if out.status.success() {
            let pkg = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Err(anyhow!(
                "{} is owned by a dpkg package ({pkg}); refusing to overwrite. \
                 Uninstall that package first.",
                dest.display()
            ));
        }
    }
    Ok(())
}

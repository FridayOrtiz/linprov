//! Copy the running binary to `/usr/local/bin/linprov`.
//!
//! `cargo install linprov` drops the binary in `~/.cargo/bin/`, which
//! isn't on root's `secure_path`. So `sudo linprov ...` fails with
//! `command not found` until we put a copy in a system-wide spot.
//! `setup` and `upgrade` both call into here.

use std::{
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

//! "Are you root?" helper that self-elevates via `sudo` when called
//! from a user shell.
//!
//! Common case: user runs `linprov setup` from their normal shell.
//! Instead of erroring out, we re-exec ourselves under `sudo` with
//! the absolute path to the current binary plus the original argv —
//! sudo prompts for the password and runs the privileged copy. The
//! original process is replaced via `execvp`, so on success this
//! function never returns. On failure (sudo not on `PATH`, sudo
//! authentication denied, etc.) we surface a helpful error
//! describing exactly what we tried to do.

use std::{env, ffi::OsString, os::unix::process::CommandExt, process::Command};

use anyhow::{anyhow, Context, Result};

pub fn require_root(action: &str) -> Result<()> {
    // SAFETY: `geteuid` is async-signal-safe and never fails.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    let exe = env::current_exe().context("locating linprov binary")?;
    let argv: Vec<OsString> = env::args_os().skip(1).collect();

    // `CommandExt::exec` replaces this process on success — if sudo
    // launches, we never see the next line. On failure (sudo missing,
    // exec-time syscall error, etc.) it returns an `io::Error`.
    let err = Command::new("sudo").arg("--").arg(&exe).args(&argv).exec();

    // Render argv for the error message. Best-effort lossy UTF-8 is
    // fine here since this is a copy-paste hint, not machine input.
    let argv_str: Vec<String> = argv
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    Err(anyhow!(
        "`{action}` needs root, and re-executing under `sudo` to ask for \
         a password failed: {err}.\n\
         \n\
         If your system uses a different escalation tool (`doas`, `su`, \
         `pkexec`, ...), invoke it on this command directly:\n\
         \n  {} {}\n",
        exe.display(),
        argv_str.join(" "),
    ))
}

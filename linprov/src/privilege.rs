//! "Are you root?" helper that returns a useful error when called
//! from a user shell.
//!
//! The common failure mode is `cargo install linprov` (which lands
//! the binary at `~/.cargo/bin/linprov`) followed by `sudo linprov
//! setup` — sudo strips `PATH` so it can't find the binary. Instead
//! of a confusing `command not found` or EACCES on `/etc/linprov/`,
//! we surface the absolute path of the running binary and the
//! literal command to copy-paste.

use std::env;

use anyhow::{anyhow, Result};

pub fn require_root(action: &str) -> Result<()> {
    // SAFETY: `geteuid` is async-signal-safe and never fails.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    let exe = env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "linprov".to_string());
    let argv: Vec<String> = env::args().skip(1).collect();
    Err(anyhow!(
        "`{action}` needs root. sudo strips PATH so it can't see\n\
         `linprov` in your user's cargo bin — invoke it by its full path:\n\
         \n  sudo {exe} {}\n",
        argv.join(" "),
    ))
}

//! `linprov upgrade` — restart the systemd unit after `cargo install
//! --force linprov` lays down a new binary.
//!
//! Doesn't touch your config or allowlist; just `systemctl daemon-reload`
//! and `systemctl restart <unit>`. If the new binary's path differs
//! from the unit's `ExecStart`, we surface that as a warning — the user
//! should re-run `linprov setup --force --binary <new-path>` to update
//! the unit.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{info, warn};

use crate::{
    config::{DEFAULT_SYSTEMD_UNIT_NAME, DEFAULT_SYSTEMD_UNIT_PATH},
    privilege,
};

#[derive(Parser, Debug)]
pub struct UpgradeArgs {
    /// Name of the systemd unit to restart.
    #[arg(long, default_value = DEFAULT_SYSTEMD_UNIT_NAME)]
    unit: String,

    /// Path to the unit file on disk. Inspected to confirm the
    /// `ExecStart` path still matches the running binary.
    #[arg(long, default_value = DEFAULT_SYSTEMD_UNIT_PATH)]
    unit_file: PathBuf,

    /// Don't actually run systemctl; print what would happen.
    #[arg(long)]
    dry_run: bool,
}

pub fn run(args: UpgradeArgs) -> Result<()> {
    if !args.dry_run {
        privilege::require_root("linprov upgrade")?;
    }
    check_exec_start_matches(&args.unit_file)?;
    systemctl(&args.unit, args.dry_run)
}

fn check_exec_start_matches(unit_file: &Path) -> Result<()> {
    let unit = match fs::read_to_string(unit_file) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                "systemd unit `{}` not found — `linprov setup` hasn't run \
                 on this host, or it wrote a unit somewhere else. Skipping \
                 the ExecStart drift check.",
                unit_file.display()
            );
            return Ok(());
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading `{}`", unit_file.display()));
        }
    };

    let exec_start = unit
        .lines()
        .find_map(|l| l.strip_prefix("ExecStart="))
        .map(str::trim);
    let Some(exec_line) = exec_start else {
        warn!(
            "unit `{}` has no ExecStart= line; can't verify the binary path matches.",
            unit_file.display()
        );
        return Ok(());
    };

    let unit_binary = exec_line.split_whitespace().next().unwrap_or("");
    let current = env::current_exe().context("locating linprov binary")?;
    if Path::new(unit_binary) != current {
        warn!(
            "unit ExecStart points at `{unit_binary}` but the running \
             `linprov upgrade` binary is `{}`. After cargo installed a \
             new binary to a different path, the systemd unit is still \
             pinned to the old one. Re-run `linprov setup --force \
             --binary {}` to update.",
            current.display(),
            current.display()
        );
    } else {
        info!(
            "ExecStart matches the current binary ({})",
            current.display()
        );
    }
    Ok(())
}

fn systemctl(unit: &str, dry_run: bool) -> Result<()> {
    let cmds: &[&[&str]] = &[
        &["systemctl", "daemon-reload"],
        &["systemctl", "restart", unit],
    ];
    for cmd in cmds {
        if dry_run {
            println!("would run: {}", cmd.join(" "));
            continue;
        }
        info!("running: {}", cmd.join(" "));
        let status = Command::new(cmd[0])
            .args(&cmd[1..])
            .status()
            .with_context(|| format!("invoking `{}`", cmd.join(" ")))?;
        if !status.success() {
            return Err(anyhow!("`{}` exited {:?}", cmd.join(" "), status.code()));
        }
    }
    if !dry_run {
        info!("linprov restarted. Tail with: journalctl -u {unit} -f");
    }
    Ok(())
}

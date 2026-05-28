//! `linprov upgrade` — copy the running binary over the system-wide
//! install path, reload systemd, restart the daemon.
//!
//! Expected flow: `cargo install --force linprov` drops a fresh
//! binary in `~/.cargo/bin/`; the user runs
//! `sudo $(which linprov) upgrade`, which copies that binary over
//! `/usr/local/bin/linprov` and bounces the unit.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{info, warn};

use crate::{
    config::{DEFAULT_INSTALL_PATH, DEFAULT_SYSTEMD_UNIT_NAME, DEFAULT_SYSTEMD_UNIT_PATH},
    install, privilege,
};

#[derive(Parser, Debug)]
pub struct UpgradeArgs {
    /// Name of the systemd unit to restart.
    #[arg(long, default_value = DEFAULT_SYSTEMD_UNIT_NAME)]
    unit: String,

    /// Path to the unit file on disk. Inspected to confirm the
    /// `ExecStart` path still matches the install path.
    #[arg(long, default_value = DEFAULT_SYSTEMD_UNIT_PATH)]
    unit_file: PathBuf,

    /// System-wide install path; copied from the currently-running
    /// executable, then systemd is restarted to pick up the new bytes.
    #[arg(long, default_value = DEFAULT_INSTALL_PATH)]
    install_path: PathBuf,

    /// Don't copy the binary, just `daemon-reload` + `restart`.
    #[arg(long)]
    no_install: bool,

    /// Don't actually run systemctl or copy; print what would happen.
    #[arg(long)]
    dry_run: bool,
}

pub fn run(args: UpgradeArgs) -> Result<()> {
    if !args.dry_run {
        privilege::require_root("linprov upgrade")?;
    }
    if !args.no_install {
        let current = install::current_exe()?;
        if args.dry_run {
            println!(
                "would copy {} -> {}",
                current.display(),
                args.install_path.display()
            );
        } else {
            install::refuse_distro_owned(&args.install_path)?;
            match install::install_to(&current, &args.install_path)? {
                install::Outcome::Installed => info!(
                    "refreshed `{}` from the running binary",
                    args.install_path.display()
                ),
                install::Outcome::AlreadyCurrent => info!(
                    "`{}` already matches the running binary",
                    args.install_path.display()
                ),
            }
        }
    }
    check_exec_start_matches(&args.unit_file, &args.install_path)?;
    systemctl(&args.unit, args.dry_run)
}

fn check_exec_start_matches(unit_file: &Path, install_path: &Path) -> Result<()> {
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
    if Path::new(unit_binary) != install_path {
        warn!(
            "unit ExecStart points at `{unit_binary}` but the install \
             path is `{}`. The unit will keep running the old binary \
             until you re-run `linprov setup --force` to rewrite it.",
            install_path.display(),
        );
    } else {
        info!(
            "ExecStart matches the install path ({})",
            install_path.display()
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

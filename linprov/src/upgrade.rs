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

    /// System-wide install path; the copy destination. Defaults to
    /// `/usr/local/bin/linprov` (matches what `setup` wrote).
    #[arg(long, default_value = DEFAULT_INSTALL_PATH)]
    install_path: PathBuf,

    /// Explicit source binary. Default: `$SUDO_USER`'s
    /// `~/.cargo/bin/linprov` (where `cargo install --force linprov`
    /// just laid down a fresh build), falling back to the currently-
    /// running executable if that lookup fails.
    #[arg(long)]
    source: Option<PathBuf>,

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

    // Skip systemctl when the source was already byte-identical to
    // the install path. Otherwise we'd bounce the daemon for nothing
    // — which is wasteful and surprises people who run
    // `linprov upgrade` to check whether they're up-to-date.
    let mut changed = true;
    if !args.no_install {
        let source = resolve_source(args.source.as_deref(), &args.install_path)?;
        if args.dry_run {
            println!(
                "would copy {} -> {}",
                source.display(),
                args.install_path.display()
            );
        } else {
            install::refuse_distro_owned(&args.install_path)?;
            match install::install_to(&source, &args.install_path)? {
                install::Outcome::Installed => info!(
                    "refreshed `{}` from `{}`",
                    args.install_path.display(),
                    source.display(),
                ),
                install::Outcome::AlreadyCurrent => {
                    info!(
                        "`{}` already matches `{}` — nothing to do",
                        args.install_path.display(),
                        source.display(),
                    );
                    changed = false;
                }
            }
        }
    }
    check_exec_start_matches(&args.unit_file, &args.install_path)?;
    if !changed {
        info!("skipping systemctl restart (no new bytes installed)");
        return Ok(());
    }
    systemctl(&args.unit, args.dry_run)
}

/// Pick the binary to copy *from*. Priority:
///   1. `--source <path>` (explicit override)
///   2. Heuristic chain in [`install::cargo_install_source`] —
///      sudo / doas / pkexec / logname / euid home / unique-match
///      scan
///   3. The currently-running binary
///
/// If none give us a path that differs from `install_path`, surface a
/// hard error — silently bouncing the daemon when the user thinks
/// they're upgrading is the worst outcome.
fn resolve_source(explicit: Option<&Path>, install_path: &Path) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = install::cargo_install_source() {
        info!(
            "found a freshly-installed binary at `{}`; using it as the upgrade source",
            p.display()
        );
        return Ok(p);
    }
    let current = install::current_exe()?;
    if same_path(&current, install_path) {
        return Err(anyhow!(
            "no upgrade source: the running binary IS `{}`, and we couldn't \
             auto-detect a `~/.cargo/bin/linprov` anywhere on this host. \
             Either run `cargo install --force linprov` as a normal user, \
             or point at the new binary explicitly:\n\n  \
             sudo linprov upgrade --source /path/to/new/linprov\n",
            install_path.display()
        ));
    }
    Ok(current)
}

fn same_path(a: &Path, b: &Path) -> bool {
    fs::canonicalize(a)
        .and_then(|ac| fs::canonicalize(b).map(|bc| ac == bc))
        .unwrap_or(false)
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

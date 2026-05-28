//! `linprov setup` — first-time install helper.
//!
//! Non-interactive: feature-detects the kernel/LSM/BTF, writes a
//! default config + empty allowlist under `/etc/linprov/`, drops a
//! systemd unit, then prints the next-step commands.

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{info, warn};

use crate::config::{
    DEFAULT_ALLOWLIST_PATH, DEFAULT_CONFIG_PATH, DEFAULT_LOG_PATH, DEFAULT_SYSTEMD_UNIT_PATH,
};

#[derive(Parser, Debug)]
pub struct SetupArgs {
    /// Where to write `config.toml`. Created if missing. Parent dirs
    /// (e.g. `/etc/linprov/`) are created with mode 0755.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Where to write the empty starting allowlist.
    #[arg(long, default_value = DEFAULT_ALLOWLIST_PATH)]
    allowlist: PathBuf,

    /// Log file path baked into the written config. The daemon will
    /// append to it; rotate via logrotate / journald-side handling.
    #[arg(long, default_value = DEFAULT_LOG_PATH)]
    log_file: PathBuf,

    /// Path to the installed linprov binary. Defaults to the current
    /// executable (whatever `cargo install` put on `$PATH`); embedded
    /// into the systemd unit's `ExecStart`.
    #[arg(long)]
    binary: Option<PathBuf>,

    /// Where to write the systemd unit. `linprov setup --no-systemd`
    /// skips writing the unit altogether.
    #[arg(long, default_value = DEFAULT_SYSTEMD_UNIT_PATH)]
    systemd_unit: PathBuf,

    /// Skip writing the systemd unit. Useful if you manage the service
    /// some other way (`runit`, manual `nohup`, container, etc.).
    #[arg(long)]
    no_systemd: bool,

    /// Overwrite existing files. By default `setup` refuses to clobber
    /// a config or systemd unit that's already there.
    #[arg(long)]
    force: bool,
}

pub fn run(args: SetupArgs) -> Result<()> {
    preflight();

    let binary = match args.binary {
        Some(p) => p,
        None => env::current_exe().context("locating linprov binary")?,
    };

    write_config(&args.config, &args.allowlist, &args.log_file, args.force)?;
    write_empty_allowlist(&args.allowlist, args.force)?;

    if !args.no_systemd {
        write_systemd_unit(&args.systemd_unit, &binary, &args.config, args.force)?;
    }

    println!();
    println!("linprov is set up.");
    println!("  config:    {}", args.config.display());
    println!("  allowlist: {}", args.allowlist.display());
    println!("  log file:  {}", args.log_file.display());
    if !args.no_systemd {
        println!("  unit:      {}", args.systemd_unit.display());
        println!();
        println!("Next steps:");
        println!("  sudo systemctl daemon-reload");
        println!("  sudo systemctl enable --now linprov.service");
        println!("  journalctl -u linprov.service -f");
    } else {
        println!();
        println!("Next steps (no-systemd):");
        println!(
            "  sudo {} run --config {}",
            binary.display(),
            args.config.display()
        );
    }
    Ok(())
}

/// Kernel / BPF LSM / BTF checks. Don't fail — just warn — so a user
/// who knows what they're doing can still `setup` on a kernel that
/// doesn't yet have BPF LSM in `lsm=`.
fn preflight() {
    match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.split(',').any(|m| m == "bpf") {
                info!("BPF LSM is active ({trimmed})");
            } else {
                warn!(
                    "BPF LSM not in the active lsm= boot parameter ({trimmed}); \
                     linprov won't be able to attach until you reboot with `bpf` in `lsm=`."
                );
            }
        }
        Err(e) => warn!(
            "couldn't read /sys/kernel/security/lsm ({e}); securityfs is \
             usually mounted at boot — is `CONFIG_SECURITY` enabled?"
        ),
    }

    if Path::new("/sys/kernel/btf/vmlinux").exists() {
        info!("vmlinux BTF is present");
    } else {
        warn!(
            "/sys/kernel/btf/vmlinux is missing — kernel needs to be \
             built with `CONFIG_DEBUG_INFO_BTF=y`."
        );
    }
}

fn write_config(path: &Path, allowlist: &Path, log_file: &Path, force: bool) -> Result<()> {
    refuse_clobber(path, force, "config")?;
    ensure_parent(path)?;

    let body = format!(
        r#"# linprov config. Loaded by `linprov run --config {0}` and by
# the systemd unit that `linprov setup` drops. Re-run `linprov setup
# --force` to regenerate; you can edit by hand any time.

# observe = log only (default)
# soak    = log + append allowlist rules for each PROVENANCE-EXEC
# enforce = block marked execve whose origin doesn't match a rule
mode = "observe"

# Path to the allowlist file. Same format the daemon writes in soak
# mode: one rule per line, AND within a line, OR across lines.
allowlist = "{1}"

# Where the daemon writes its logs. Comment out to send logs to stderr
# instead (e.g. when journald is already capturing them).
log_file = "{2}"

# trace | debug | info | warn | error
log_level = "info"

# By default, connect()s to 127.0.0.0/8 and ::1 don't mark the PID as
# network-touched. Flip to `true` to include them (e.g. on a system
# where you treat localhost downloads as real network activity).
mark_localhost = false

# Dimensions soak mode bundles into each emitted rule. Each
# PROVENANCE-EXEC writes one allowlist line whose conditions all of
# these dims AND together. The default keeps things simple — one rule
# per creator binary — but you can mix `creator_uid`, `target_folder`,
# `landing_filename`, etc.
soak = ["creator_process"]
"#,
        path.display(),
        allowlist.display(),
        log_file.display(),
    );
    fs::write(path, body).with_context(|| format!("writing `{}`", path.display()))?;
    info!("wrote config: {}", path.display());
    Ok(())
}

fn write_empty_allowlist(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        info!(
            "allowlist already exists at {}, leaving alone",
            path.display()
        );
        return Ok(());
    }
    ensure_parent(path)?;
    let body = "# linprov allowlist. One rule per line; conditions within a line\n\
                # AND together; multiple lines OR. Example:\n\
                #   creator_uid=1000;creator_comm=curl\n\
                #   execution_uid=1000;creator_comm=firefox;target_folder=/home/user/.local/bin\n";
    fs::write(path, body).with_context(|| format!("writing `{}`", path.display()))?;
    info!("wrote empty allowlist: {}", path.display());
    Ok(())
}

fn write_systemd_unit(unit_path: &Path, binary: &Path, config: &Path, force: bool) -> Result<()> {
    refuse_clobber(unit_path, force, "systemd unit")?;
    ensure_parent(unit_path)?;
    let body = format!(
        r#"[Unit]
Description=linprov: eBPF mark-of-the-web for Linux
Documentation=https://github.com/FridayOrtiz/linprov
After=network.target

[Service]
Type=simple
ExecStart={0} run --config {1}
Restart=on-failure
RestartSec=5s

# linprov needs root to load the BPF program, attach LSM hooks, and
# write `security.bpf.linprov.origin` xattrs across the filesystem.
User=root

[Install]
WantedBy=multi-user.target
"#,
        binary.display(),
        config.display(),
    );
    fs::write(unit_path, body).with_context(|| format!("writing `{}`", unit_path.display()))?;
    // Be tidy: unit files are world-readable.
    let _ = fs::set_permissions(unit_path, fs::Permissions::from_mode(0o644));
    info!("wrote systemd unit: {}", unit_path.display());
    Ok(())
}

fn refuse_clobber(path: &Path, force: bool, label: &str) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "{label} already exists at `{}`. Pass --force to overwrite.",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating `{}`", parent.display()))?;
        }
    }
    Ok(())
}

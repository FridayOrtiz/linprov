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

use crate::{
    config::{DEFAULT_ALLOWLIST_PATH, DEFAULT_CONFIG_PATH, DEFAULT_SYSTEMD_UNIT_PATH},
    privilege,
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
    privilege::require_root("linprov setup")?;
    preflight();

    let binary = match args.binary {
        Some(p) => p,
        None => env::current_exe().context("locating linprov binary")?,
    };

    write_config(&args.config, &args.allowlist, args.force)?;
    write_empty_allowlist(&args.allowlist, args.force)?;

    if !args.no_systemd {
        write_systemd_unit(&args.systemd_unit, &binary, &args.config, args.force)?;
    }

    println!();
    println!("linprov is set up.");
    println!("  config:    {}", args.config.display());
    println!("  allowlist: {}", args.allowlist.display());
    if !args.no_systemd {
        println!("  unit:      {}", args.systemd_unit.display());
    }
    println!();
    println!(
        "Recommended next steps — soak first, then enforce. Don't enable the\n\
         systemd unit yet; you want to build up an allowlist before anything\n\
         gets blocked."
    );
    println!();
    println!("  # 1. Run a soak in the foreground. Use your machine normally —");
    println!(
        "  #    every marked execve appends a rule to {}.",
        args.allowlist.display()
    );
    println!(
        "  #    `^C` when you're satisfied; the rules persist in the file.\n\
         \n  sudo {} run --mode soak\n",
        binary.display()
    );
    println!("  # 2. Review the allowlist.");
    println!("  cat {}\n", args.allowlist.display());
    println!(
        "  # 3. Edit {} and flip `mode` from\n  #    \"observe\" to \"enforce\".",
        args.config.display()
    );
    if !args.no_systemd {
        println!();
        println!("  # 4. Enable the systemd unit.");
        println!("  sudo systemctl daemon-reload");
        println!("  sudo systemctl enable --now linprov.service");
        println!("  journalctl -u linprov.service -f");
    } else {
        println!();
        println!("  # 4. Run the daemon (whatever supervises it on your system).");
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

fn write_config(path: &Path, allowlist: &Path, force: bool) -> Result<()> {
    refuse_clobber(path, force, "config")?;
    ensure_parent(path)?;

    let body = format!(
        r#"# linprov config. Loaded by `linprov run --config {0}` and by
# the systemd unit that `linprov setup` drops. Re-run `linprov setup
# --force` to regenerate; edit by hand any time.

# observe = log only (safe default — never blocks)
# soak    = log + append a rule to `allowlist` for each marked execve
# enforce = block any marked execve whose origin doesn't match a rule
#
# Suggested workflow:
#   1. `sudo linprov run --mode soak` — use your machine normally for
#      a while; rules accumulate in the allowlist below.
#   2. Skim the allowlist; trim anything you don't actually want
#      permitted.
#   3. Flip the line below to `mode = "enforce"`.
#   4. Enable the systemd unit (`sudo systemctl enable --now
#      linprov.service`) — or `linprov upgrade` if it's already
#      running.
mode = "observe"

# One rule per line; conditions within a line AND, lines OR.
allowlist = "{1}"

# trace | debug | info | warn | error
log_level = "info"

# By default, connect()s to 127.0.0.0/8 and ::1 don't mark the PID
# as network-touched. Flip to `true` to include them.
mark_localhost = false

# Dimensions soak mode AND-joins into each emitted rule. Default keeps
# things simple — one rule per distinct creator binary — but you can
# mix `creator_uid`, `target_folder`, `landing_filename`, etc.
soak = ["creator_process"]

# Optional: append logs to a file instead of stderr. Leave commented
# out under systemd — journald captures stderr automatically. Useful
# if you run linprov outside of systemd (`runit`, manual, container).
# log_file = "/var/log/linprov.log"
"#,
        path.display(),
        allowlist.display(),
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

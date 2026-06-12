//! `linprov setup` — first-time install helper.
//!
//! Feature-detects the kernel/LSM/BTF, writes a default config + empty
//! allowlist under `/etc/linprov/`, and drops a systemd unit. On a TTY
//! it then walks the user through the observe → soak → enforce model
//! and, on a graphical session, optionally wires up the desktop tray UI
//! (`notifications = "tray"`, group membership, a `systemd --user`
//! service). `--yes` / a non-TTY stdin skips the walkthrough and just
//! prints the next-step commands.

use std::{
    fs,
    io::{IsTerminal, Write},
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{info, warn};

use crate::{
    config::{
        DEFAULT_ALLOWLIST_PATH, DEFAULT_CONFIG_PATH, DEFAULT_INSTALL_PATH,
        DEFAULT_SYSTEMD_UNIT_PATH,
    },
    install, privilege,
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

    /// System-wide install path for the linprov binary. Copied from
    /// the currently-running executable on every `setup` / `upgrade`.
    /// `/usr/local/bin/` is on root's `secure_path` so subsequent
    /// `sudo linprov ...` invocations work without an absolute path.
    #[arg(long, default_value = DEFAULT_INSTALL_PATH)]
    install_path: PathBuf,

    /// Don't copy the binary anywhere — use the currently-running
    /// executable in place. The systemd unit's `ExecStart` will point
    /// at wherever this binary already lives, which means `sudo
    /// linprov` won't work unless that path is on root's `secure_path`.
    #[arg(long)]
    no_install: bool,

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

    /// Skip the interactive walkthrough: just write the files, ensure
    /// the group, drop the systemd unit, and print next steps (the
    /// classic non-interactive behavior). Implied automatically when
    /// stdin/stdout aren't a TTY (pipes, CI).
    #[arg(long, short = 'y')]
    yes: bool,
}

pub fn run(args: SetupArgs) -> Result<()> {
    privilege::require_root("linprov setup")?;
    preflight();

    let current = install::current_exe()?;
    let binary = if args.no_install {
        current.clone()
    } else {
        install::refuse_distro_owned(&args.install_path)?;
        match install::install_to(&current, &args.install_path)? {
            install::Outcome::Installed => {
                info!(
                    "copied running binary into `{}`",
                    args.install_path.display()
                );
            }
            install::Outcome::AlreadyCurrent => {
                info!(
                    "`{}` already matches the running binary",
                    args.install_path.display()
                );
            }
        }
        args.install_path.clone()
    };

    write_config(&args.config, &args.allowlist, args.force)?;
    write_empty_allowlist(&args.allowlist, args.force)?;
    ensure_linprov_group();

    if !args.no_systemd {
        write_systemd_unit(&args.systemd_unit, &binary, &args.config, args.force)?;
    }

    println!();
    println!("linprov is set up.");
    if !args.no_install {
        println!("  binary:    {}", binary.display());
    }
    println!("  config:    {}", args.config.display());
    println!("  allowlist: {}", args.allowlist.display());
    if !args.no_systemd {
        println!("  unit:      {}", args.systemd_unit.display());
    }
    println!();
    // After a self-install the binary lives in `/usr/local/bin/`,
    // which is on root's `secure_path`, so `sudo linprov` resolves
    // without an absolute path. Use that in the next-steps output.
    let invoke = if args.no_install {
        binary.display().to_string()
    } else {
        "linprov".to_string()
    };
    if interactive(args.yes) {
        walkthrough(&args, &binary, &invoke)?;
    } else {
        print_next_steps(&args, &invoke);
    }
    Ok(())
}

/// The classic, non-interactive next-steps block (also used as the
/// fallback when there's no TTY). Pure print — changes nothing.
fn print_next_steps(args: &SetupArgs, invoke: &str) {
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
         \n  sudo {invoke} run --mode soak\n",
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
        println!("  sudo {invoke} run --config {}", args.config.display());
    }
}

/// Interactive when both ends are a TTY and the user didn't pass
/// `--yes`. `sudo` self-elevation (privilege::require_root) keeps the
/// controlling terminal, so this stays true after the re-exec.
fn interactive(yes: bool) -> bool {
    !yes && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Parse a yes/no answer; empty (just Enter) or anything unrecognized
/// takes `default_yes`.
fn parse_yes_no(input: &str, default_yes: bool) -> bool {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default_yes,
    }
}

fn prompt_yes_no(question: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{question} {hint} ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading your answer from stdin")?;
    Ok(parse_yes_no(&line, default_yes))
}

/// The guided tail of `linprov setup`: explain the model, optionally
/// wire up the desktop tray UI (config + group + per-user systemd
/// service), then offer to drop straight into a soak. Every system
/// change is gated on a y/n prompt; declining anything just prints the
/// command instead.
fn walkthrough(args: &SetupArgs, binary: &Path, invoke: &str) -> Result<()> {
    println!("Let's finish setup — I'll ask before changing anything.\n");
    println!("linprov has three modes: observe (log only), soak (log + learn an");
    println!("allowlist), and enforce (block execs whose origin isn't allowed).");
    println!("The usual path: soak while you work, review the rules, flip to enforce.\n");

    // --- Desktop tray UI -------------------------------------------------
    let user = install::invoking_user();
    let desktop = user.as_ref().map(graphical_session).unwrap_or(false);
    if desktop {
        if prompt_yes_no(
            "Set up the desktop tray UI now (a tray icon to Allow once / always)?",
            true,
        )? {
            // desktop && user is Some
            let user = user.as_ref().unwrap();
            setup_tray_ui(args, binary, user)?;
        }
    } else {
        println!("No graphical session detected — skipping the desktop tray UI.");
        println!("(Set it up later on a desktop; see the README \"Desktop tray UI\".)\n");
    }

    // --- Enforce reminder + optional restart -----------------------------
    print_enforce_reminder(args, invoke);
    if systemd_unit_active()
        && prompt_yes_no(
            "\nlinprov.service is running. Restart it now so config changes take effect?",
            false,
        )?
    {
        restart_system_unit();
    }

    // --- Soak (last: it replaces this process) ---------------------------
    println!();
    if prompt_yes_no(
        "Start a foreground soak now? (use your machine normally; ^C when done)",
        false,
    )? {
        println!("\nStarting `{invoke} run --mode soak` — ^C to stop.\n");
        // Replace this process with the soak daemon (we're already root).
        let err = Command::new(binary).args(["run", "--mode", "soak"]).exec();
        return Err(anyhow!("couldn't start the soak daemon ({err})"));
    }
    println!("\nWhen you're ready to soak:  sudo {invoke} run --mode soak");
    Ok(())
}

/// Wire up the tray agent for `user`: enable `notifications = "tray"`,
/// add them to the `linprov` group, and install + enable a per-user
/// systemd service. Each step is individually confirmed.
fn setup_tray_ui(args: &SetupArgs, binary: &Path, user: &install::InvokingUser) -> Result<()> {
    if prompt_yes_no(
        &format!(
            "  → set notifications = \"tray\" in {}?",
            args.config.display()
        ),
        true,
    )? {
        set_config_notifications_tray(&args.config)?;
        info!("enabled tray notifications in {}", args.config.display());
    }

    // Track whether *this run* added the user to the group: if so, the live
    // `systemd --user` manager still has stale groups and the per-user service
    // can't connect until a full re-login (warned about below).
    let mut joined_group = false;
    if prompt_yes_no(
        &format!(
            "  → add `{}` to the `linprov` group (usermod -aG linprov {})?",
            user.name, user.name
        ),
        true,
    )? {
        if user_in_linprov_group(&user.name) {
            println!("    `{}` is already in the `linprov` group.", user.name);
        } else {
            add_user_to_group(&user.name)?;
            joined_group = true;
            println!("    added — takes effect on your next login (or `newgrp linprov`).");
        }
    }

    if prompt_yes_no(
        "  → install + enable a systemd --user service so the tray autostarts?",
        true,
    )? {
        let unit = write_user_notify_unit(user, binary)?;
        info!("wrote {}", unit.display());
        enable_user_unit(user, joined_group);
    }

    println!();
    println!("Using it:");
    println!("  • The tray icon lists recent blocked execs; each offers Allow once /");
    println!("    Allow always / Close.");
    println!("  • Or from the shell, with the token in each BLOCKED-* log line:");
    println!(
        "      sudo {0} allow <token>         # permanent (appends to the allowlist)",
        invoke_for(args, binary)
    );
    println!(
        "      sudo {0} allow --once <token>  # this session only (in memory)",
        invoke_for(args, binary)
    );
    println!("  • Needs a StatusNotifierHost — on sway, waybar's `tray` module.");
    println!();
    Ok(())
}

/// `linprov` (post-install, on root's `secure_path`) or the explicit
/// binary path when `--no-install` left it elsewhere.
fn invoke_for(args: &SetupArgs, binary: &Path) -> String {
    if args.no_install {
        binary.display().to_string()
    } else {
        "linprov".to_string()
    }
}

/// A graphical session for `user`? `sudo` usually strips
/// `WAYLAND_DISPLAY`/`DISPLAY` from our env, so look at the user's
/// runtime dir for a compositor socket instead, with an env fallback.
fn graphical_session(user: &install::InvokingUser) -> bool {
    let run = PathBuf::from(format!("/run/user/{}", user.uid));
    if let Ok(entries) = fs::read_dir(&run) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("wayland-") {
                return true;
            }
        }
    }
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

/// Ensure the config has an active `notifications = "tray"` line —
/// replacing the commented hint (or a prior value), appending if absent.
/// Idempotent.
fn set_config_notifications_tray(path: &Path) -> Result<()> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    fs::write(path, ensure_tray_line(&text)).with_context(|| format!("writing {}", path.display()))
}

/// Pure transform behind [`set_config_notifications_tray`]: rewrite the
/// first `notifications`-mentioning line (commented or not) to an active
/// `notifications = "tray"`, or append one if there's none.
fn ensure_tray_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 24);
    let mut done = false;
    for line in text.lines() {
        let bare = line.trim_start().trim_start_matches('#').trim_start();
        if !done && bare.starts_with("notifications") {
            out.push_str("notifications = \"tray\"\n");
            done = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !done {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("notifications = \"tray\"\n");
    }
    out
}

fn add_user_to_group(user: &str) -> Result<()> {
    let status = Command::new("usermod")
        .args(["-aG", "linprov", user])
        .status()
        .context("running usermod")?;
    if !status.success() {
        return Err(anyhow!("usermod -aG linprov {user} exited {status}"));
    }
    Ok(())
}

/// Write `~/.config/systemd/user/linprov-notify.service` for `user`,
/// owned by them (we run as root). `PartOf`/`WantedBy`
/// graphical-session.target so it tracks the desktop session.
fn write_user_notify_unit(user: &install::InvokingUser, binary: &Path) -> Result<PathBuf> {
    let cfg = user.home.join(".config");
    let sd = cfg.join("systemd");
    let dir = sd.join("user");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let unit = dir.join("linprov-notify.service");
    // WantedBy=default.target (not graphical-session.target): the user
    // manager always reaches default.target at login, whereas
    // graphical-session.target is only activated by compositors that wire it
    // up — bare sway doesn't, so a graphical-session-bound unit silently never
    // autostarts. The agent retries tray registration, so starting a touch
    // early (before the tray host) is harmless.
    let body = format!(
        "[Unit]\n\
         Description=linprov desktop tray agent\n\
         Documentation=https://github.com/FridayOrtiz/linprov\n\
         After=graphical-session.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} notify\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        binary.display(),
    );
    fs::write(&unit, body).with_context(|| format!("writing {}", unit.display()))?;
    // Hand ownership of anything we just created back to the user. Each
    // chown is node-level (not recursive); re-chowning an already
    // user-owned dir to the same user is a harmless no-op.
    for p in [unit.as_path(), dir.as_path(), sd.as_path(), cfg.as_path()] {
        chown_to_user(p, user);
    }
    Ok(unit)
}

fn chown_to_user(path: &Path, user: &install::InvokingUser) {
    let _ = std::os::unix::fs::chown(path, Some(user.uid), Some(user.gid));
}

/// `systemctl --user daemon-reload` + `enable --now`, run *as the user*
/// (we're root) by dropping uid/gid and pointing at their session bus.
/// `--now` starts it immediately if the session is live; otherwise the
/// `enable` persists for the next graphical login. `joined_group` flags
/// that we *just* added the user to `linprov` — in which case the running
/// `systemd --user` manager still has stale groups and the service can't
/// connect until a full re-login, so we say so.
fn enable_user_unit(user: &install::InvokingUser, joined_group: bool) {
    let runtime = format!("/run/user/{}", user.uid);
    let bus = format!("unix:path={runtime}/bus");
    let run = |sub: &[&str]| -> std::io::Result<std::process::ExitStatus> {
        Command::new("systemctl")
            .arg("--user")
            .args(sub)
            .uid(user.uid)
            .gid(user.gid)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("DBUS_SESSION_BUS_ADDRESS", &bus)
            .env("HOME", &user.home)
            .status()
    };
    let _ = run(&["daemon-reload"]);
    match run(&["enable", "--now", "linprov-notify.service"]) {
        Ok(s) if s.success() => {
            info!("enabled + started linprov-notify.service (systemd --user)");
            if joined_group {
                warn!(
                    "…but you were just added to the `linprov` group, and the \
                     running systemd --user manager still has your old groups — \
                     so the service can't reach the control socket until you \
                     fully log out and back in (or reboot). `systemctl --user \
                     restart` won't refresh it; a full re-login will, and the \
                     tray then connects automatically."
                );
            }
        }
        _ => warn!(
            "couldn't enable/start the user service right now (no live user \
             session, e.g. over SSH?); it's enabled and will start on your next \
             login. Check with `systemctl --user status linprov-notify`."
        ),
    }
}

/// Does `user` already belong to the `linprov` group (per the group DB)?
fn user_in_linprov_group(user: &str) -> bool {
    Command::new("id")
        .args(["-nG", user])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|g| g == "linprov")
        })
        .unwrap_or(false)
}

fn systemd_unit_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "linprov.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn restart_system_unit() {
    match Command::new("systemctl")
        .args(["restart", "linprov.service"])
        .status()
    {
        Ok(s) if s.success() => info!("restarted linprov.service"),
        Ok(s) => warn!("systemctl restart linprov.service exited {s}"),
        Err(e) => warn!("couldn't restart linprov.service ({e})"),
    }
}

fn print_enforce_reminder(args: &SetupArgs, invoke: &str) {
    println!("When your allowlist looks good:");
    println!("  1. review:   cat {}", args.allowlist.display());
    println!(
        "  2. enforce:  set mode = \"enforce\" in {}",
        args.config.display()
    );
    if !args.no_systemd {
        println!("  3. enable:   sudo systemctl enable --now linprov.service");
    } else {
        println!(
            "  3. run:      sudo {invoke} run --config {}",
            args.config.display()
        );
    }
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
    // Idempotent: re-running `setup` on an existing install leaves your
    // config untouched (and still reaches the interactive walkthrough,
    // which can patch it in place). `--force` regenerates from template.
    if path.exists() && !force {
        info!("config already exists at {}, leaving alone", path.display());
        return Ok(());
    }
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

# Plaintext audit db mapping the FNV hashes stored in xattrs/records
# back to their paths. Lets the daemon log readable paths, lets soak
# emit plaintext rules, and lets you `grep` what's been marked. Persists
# across reboots; enforcement never reads it. Default shown:
# hash_db = "/var/lib/linprov/hashes.tsv"

# Desktop tray agent. "off" (default) keeps the control socket root-only.
# "tray" chmods it 0660 group `linprov` so a user-session `linprov notify`
# tray agent can subscribe to blocks and apply allows. Easiest path: re-run
# `linprov setup` on a desktop and accept the tray prompts — it sets this,
# adds you to the `linprov` group, and installs a `systemd --user` service
# that autostarts the agent. By hand: add your user to the group
# (`sudo usermod -aG linprov $USER`, re-login) and run `linprov notify` from
# your session (needs a tray host like waybar's tray module).
# notifications = "tray"

# Script interpreters (by `comm`) whose reads of a marked file are
# enforced like an execve — so `bash foo.sh` / `python foo.py` /
# `. foo.sh` honor the same policy as `./foo.sh`. A rule keyed on the
# script (target_filename / target_folder) permits both forms. Defaults
# to the common shells / runtimes (shown below). Set to `[]` to disable
# script enforcement. Note: an interpreter reading a marked *data* file
# is subject to the same check — allowlist it or trim this list.
# interpreters = ["sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "node", "php", "lua", "awk"]

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

/// Create the `linprov` group (idempotent). With `notifications = "tray"`
/// the daemon chowns its control socket to this group so a user-session
/// `linprov notify` agent can connect; the user still has to add
/// themselves (`usermod -aG linprov <user>`) and re-login. Best-effort —
/// a missing `groupadd` or non-root run just logs and moves on.
fn ensure_linprov_group() {
    match Command::new("groupadd").args(["-f", "linprov"]).status() {
        Ok(s) if s.success() => info!("ensured `linprov` group exists"),
        Ok(s) => warn!("groupadd linprov exited {s}; create it by hand if you want the tray agent"),
        Err(e) => warn!(
            "couldn't run groupadd ({e}); create the `linprov` group by hand for the tray agent"
        ),
    }
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
    // Idempotent like write_config: leave an existing unit alone unless
    // `--force` (so re-running `setup` doesn't clobber local edits).
    if unit_path.exists() && !force {
        info!(
            "systemd unit already exists at {}, leaving alone",
            unit_path.display()
        );
        return Ok(());
    }
    ensure_parent(unit_path)?;
    let body = format!(
        r#"[Unit]
Description=linprov: eBPF mark-of-the-web for Linux
Documentation=https://github.com/FridayOrtiz/linprov
After=network.target

[Service]
Type=simple
ExecStart={0} run --config {1}
# `systemctl reload linprov` → SIGHUP → re-parse the allowlist and
# re-seed the in-kernel rules live, without a restart.
ExecReload=/bin/kill -HUP $MAINPID
# systemd creates/owns /run/linprov for the control socket (cleaned up
# when the unit stops). The daemon chowns it to the `linprov` group and
# tightens/loosens perms per `notifications`; 0750 here lets the group
# traverse in `tray` mode (a 0660 socket in a 0700 dir is unreachable).
RuntimeDirectory=linprov
RuntimeDirectoryMode=0750
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

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating `{}`", parent.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_tray_line, parse_yes_no};

    #[test]
    fn yes_no_parsing() {
        for s in ["y", "Y", "yes", "YES", " yes \n"] {
            assert!(parse_yes_no(s, false), "{s:?} should be yes");
        }
        for s in ["n", "N", "no", "NO", " no \n"] {
            assert!(!parse_yes_no(s, true), "{s:?} should be no");
        }
        // Empty / unrecognized falls back to the default.
        assert!(parse_yes_no("", true));
        assert!(!parse_yes_no("", false));
        assert!(parse_yes_no("maybe", true));
        assert!(!parse_yes_no("maybe", false));
    }

    #[test]
    fn tray_line_replaces_commented_hint() {
        let cfg = "mode = \"observe\"\n# notifications = \"tray\"\nlog_level = \"info\"\n";
        let out = ensure_tray_line(cfg);
        assert!(out.contains("notifications = \"tray\"\n"));
        assert!(!out.contains("# notifications"));
        assert!(out.contains("mode = \"observe\""));
        assert!(out.contains("log_level = \"info\""));
        // Exactly one notifications line.
        assert_eq!(out.matches("notifications").count(), 1);
    }

    #[test]
    fn tray_line_replaces_prior_value() {
        let out = ensure_tray_line("notifications = \"off\"\n");
        assert_eq!(out, "notifications = \"tray\"\n");
    }

    #[test]
    fn tray_line_appended_when_absent() {
        let out = ensure_tray_line("mode = \"observe\"\n");
        assert_eq!(out, "mode = \"observe\"\nnotifications = \"tray\"\n");
    }

    #[test]
    fn tray_line_is_idempotent() {
        let once = ensure_tray_line("# notifications = \"tray\"\n");
        let twice = ensure_tray_line(&once);
        assert_eq!(once, twice);
        assert_eq!(twice.matches("notifications").count(), 1);
    }
}

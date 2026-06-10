//! linprov: eBPF mark-of-the-web for Linux.
//!
//! `linprov run` is the daemon; `linprov setup` is the first-time
//! install helper; `linprov upgrade` restarts the systemd unit after
//! a fresh `cargo install --force linprov`. See README and
//! CONTRIBUTING for the bigger picture.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod allow;
mod allowlist;
mod config;
mod control;
mod handler;
mod hashdb;
mod inode_storage;
mod install;
mod mode;
mod notify;
mod privilege;
mod run;
mod setup;
mod upgrade;

pub(crate) use mode::Mode as ModeArg;

#[derive(Parser, Debug)]
#[command(
    name = "linprov",
    version,
    about = "eBPF-based mark-of-the-web for Linux",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the daemon (used by the systemd unit).
    Run(run::RunArgs),
    /// First-time install: feature-check the host, write a default
    /// config + empty allowlist, drop a systemd unit.
    Setup(setup::SetupArgs),
    /// After `cargo install --force linprov` lays down a new binary,
    /// reload systemd and restart linprov.service.
    Upgrade(upgrade::UpgradeArgs),
    /// Permit a blocked exec by the token from its `BLOCKED-EXEC` /
    /// `BLOCKED-SCRIPT` log line. Talks to the running daemon's control
    /// socket; `--once` applies it in memory only (not persisted).
    Allow(allow::AllowArgs),
    /// User-session tray agent: subscribe to blocks over the control
    /// socket and surface Allow once / Allow always / Close in a tray
    /// menu. Run from your graphical session (e.g. sway `exec`).
    Notify(notify::NotifyArgs),
}

fn main() -> Result<()> {
    // `run` initializes its own logger from the resolved config; the
    // other subcommands get a simple stderr logger so we see the
    // setup / upgrade progress messages.
    let cli = Cli::parse();
    if !matches!(cli.command, Cmd::Run(_)) {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
    match cli.command {
        Cmd::Run(args) => run::execute(args),
        Cmd::Setup(args) => setup::run(args),
        Cmd::Upgrade(args) => upgrade::run(args),
        Cmd::Allow(args) => allow::run(args),
        Cmd::Notify(args) => notify::run(args),
    }
}

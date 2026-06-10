//! `linprov allow [--once] <token>` — permit a blocked exec by the token
//! from its `BLOCKED-EXEC` / `BLOCKED-SCRIPT` log line, by asking the
//! running daemon (over its control socket) to apply the rule that would
//! have permitted it and reseed the live BPF map.
//!
//! Without `--once` the rule is appended to the allowlist file (permanent).
//! With `--once` it's added to the daemon's in-memory transient set only:
//! active immediately and across SIGHUP reloads, never written to disk, and
//! gone when the daemon restarts.

use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;

use crate::config::DEFAULT_CONTROL_SOCKET_PATH;

#[derive(Parser, Debug)]
pub struct AllowArgs {
    /// Token from the `[allow: <token>]` suffix of a `BLOCKED-EXEC` /
    /// `BLOCKED-SCRIPT` log line.
    token: String,

    /// Apply the rule in memory only — active immediately and across SIGHUP
    /// reloads, but NOT written to the allowlist file, so it's gone when the
    /// daemon restarts.
    #[arg(long)]
    once: bool,

    /// Daemon control socket to connect to.
    #[arg(long, default_value = DEFAULT_CONTROL_SOCKET_PATH)]
    socket: PathBuf,
}

pub fn run(args: AllowArgs) -> Result<()> {
    let mut stream = UnixStream::connect(&args.socket).with_context(|| {
        format!(
            "connecting to the linprov control socket at {} \
             (is the daemon running? are you root?)",
            args.socket.display()
        )
    })?;

    let verb = if args.once { "once" } else { "allow" };
    stream
        .write_all(format!("{verb} {}\n", args.token).as_bytes())
        .context("sending request")?;
    // Half-close the write side so the daemon's single read returns.
    stream.shutdown(Shutdown::Write).ok();

    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .context("reading reply from daemon")?;
    let reply = reply.trim();

    if let Some(rule) = reply.strip_prefix("OK ") {
        let how = if args.once {
            "in memory (transient — gone on daemon restart)"
        } else {
            "persisted to the allowlist"
        };
        println!("allowed, {how}:\n  {rule}");
        Ok(())
    } else if let Some(msg) = reply.strip_prefix("ERR ") {
        Err(anyhow!("daemon rejected the request: {msg}"))
    } else {
        Err(anyhow!("unexpected reply from daemon: {reply:?}"))
    }
}

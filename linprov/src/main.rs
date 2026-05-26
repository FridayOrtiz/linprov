//! linprov userspace daemon.
//!
//! Loads the eBPF programs, attaches the tracepoints, and consumes the
//! provenance event ring buffer.

use std::os::fd::AsRawFd;

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::TracePoint,
    Ebpf,
};
use clap::Parser;
use log::{info, warn};
use tokio::{io::unix::AsyncFd, signal};

mod handler;

#[derive(Parser, Debug)]
#[command(
    name = "linprov",
    about = "eBPF-based mark-of-the-web provenance tracker"
)]
struct Args {
    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Don't actually set xattrs; just log what would be marked. Useful for
    /// dry-running on hosts where the daemon hasn't been authorized yet.
    #[arg(long)]
    dry_run: bool,
}

const EBPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/linprov-ebpf"));

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(args.log_level.clone()),
    )
    .init();

    // Lift the rlimit so the eBPF maps can actually be created. Modern kernels
    // use cgroup-based memcg accounting and don't need this, but it's cheap.
    bump_memlock_rlimit()?;

    let mut bpf = Ebpf::load(EBPF_OBJECT).context("loading eBPF object")?;

    attach_tracepoints(&mut bpf).context("attaching tracepoints")?;

    // The ring buffer map is owned by `bpf`. Taking it gives us a typed
    // `RingBuf` we can wrap in `AsyncFd` for cooperative polling under tokio.
    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("EVENTS map not found in eBPF object"))?;
    let ring_buf = RingBuf::try_from(events_map).context("opening ring buffer")?;
    let mut poll = AsyncFd::with_interest(
        RingBufFd(ring_buf),
        tokio::io::Interest::READABLE,
    )?;

    let cfg = handler::Config {
        dry_run: args.dry_run,
    };

    info!(
        "linprov running (dry_run={}). press Ctrl-C to exit.",
        args.dry_run
    );

    loop {
        tokio::select! {
            biased;

            _ = signal::ctrl_c() => {
                info!("shutdown requested");
                break;
            }

            res = poll.readable_mut() => {
                let mut guard = res.context("polling ring buffer")?;
                let ring = &mut guard.get_inner_mut().0;
                while let Some(item) = ring.next() {
                    handler::handle_event(&cfg, item.as_ref());
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

/// Newtype so we can implement `AsRawFd` for the `AsyncFd` wrapper. The Aya
/// `RingBuf` already implements `AsRawFd`, but `AsyncFd::with_interest` wants
/// ownership and we want to keep mut-access to the inner ring buffer.
struct RingBufFd(RingBuf<aya::maps::MapData>);

impl AsRawFd for RingBufFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

fn attach_tracepoints(bpf: &mut Ebpf) -> Result<()> {
    // (program function name, tracepoint category, tracepoint name)
    let attachments: &[(&str, &str, &str)] = &[
        ("sys_enter_socket", "syscalls", "sys_enter_socket"),
        ("sys_exit_socket", "syscalls", "sys_exit_socket"),
        ("sys_enter_openat", "syscalls", "sys_enter_openat"),
        ("sys_exit_openat", "syscalls", "sys_exit_openat"),
        ("sys_enter_execve", "syscalls", "sys_enter_execve"),
        ("sys_enter_execveat", "syscalls", "sys_enter_execveat"),
        ("sched_process_exit", "sched", "sched_process_exit"),
    ];

    for (prog_name, category, name) in attachments {
        let program: &mut TracePoint = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow!("eBPF program `{prog_name}` not present in object"))?
            .try_into()
            .with_context(|| format!("program `{prog_name}` is not a tracepoint"))?;
        program
            .load()
            .with_context(|| format!("loading program `{prog_name}`"))?;
        program
            .attach(category, name)
            .with_context(|| format!("attaching `{prog_name}` to {category}/{name}"))?;
        log::debug!("attached {prog_name} -> {category}/{name}");
    }
    Ok(())
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        // Non-fatal on modern kernels with memcg accounting; just warn.
        warn!(
            "setrlimit(RLIMIT_MEMLOCK, INFINITY) failed: {}. \
             eBPF map allocation may fail on older kernels.",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

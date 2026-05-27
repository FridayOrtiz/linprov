//! linprov userspace daemon.
//!
//! Loads the eBPF object (LSM programs + one cleanup tracepoint), attaches
//! everything, consumes the provenance event ring buffer, and (depending on
//! mode) maintains an AND-then-OR allowlist of marked binaries permitted
//! to execute.

use std::{os::fd::AsRawFd, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, RingBuf},
    programs::{Lsm, TracePoint},
    Btf, Ebpf,
};
use clap::{Parser, ValueEnum};
use linprov_common::{AllowRule, MAX_RULES, MODE_ENFORCE, MODE_OBSERVE, MODE_SOAK};

/// Newtype wrapper for `AllowRule` so we can `impl aya::Pod` locally
/// without falling foul of Rust's orphan rule (`AllowRule` lives in
/// linprov-common, which can't see aya).
#[repr(transparent)]
#[derive(Copy, Clone)]
struct AllowRuleWire(AllowRule);

unsafe impl aya::Pod for AllowRuleWire {}
use log::{info, warn};
use tokio::{io::unix::AsyncFd, signal};

mod allowlist;
mod handler;

use allowlist::{Dim, Rules, Soak};

#[derive(Parser, Debug)]
#[command(
    name = "linprov",
    about = "eBPF-based mark-of-the-web provenance tracker"
)]
struct Args {
    /// Operating mode.
    #[arg(long, value_enum, default_value_t = Mode::Observe)]
    mode: Mode,

    /// Allowlist file. Each line is one rule whose
    /// `<dim>=<value>;<dim>=<value>` conditions AND together. Lines OR.
    /// Required in soak and enforce modes.
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Dimensions to bundle into each soak-emitted rule. Comma-separated.
    /// Default: `creator_process` (one-dim rule per distinct creator
    /// binary). Multiple dims here mean each soak event emits a single
    /// rule that AND-matches all of them, e.g.
    /// `--soak creator_process,creator_uid` emits
    /// `creator_process=…;creator_uid=…`.
    #[arg(long, value_delimiter = ',', default_value = "creator_process")]
    soak: Vec<Dim>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum Mode {
    /// Log only; nothing enforced or recorded persistently.
    Observe,
    /// Log and append one rule per PROVENANCE-EXEC, joining all
    /// `--soak` dims into a single conjunction.
    Soak,
    /// Block execve of marked files whose origin doesn't match any
    /// allowlist rule. `-EPERM` from `security_bprm_check`.
    Enforce,
}

impl Mode {
    fn as_u32(self) -> u32 {
        match self {
            Mode::Observe => MODE_OBSERVE,
            Mode::Soak => MODE_SOAK,
            Mode::Enforce => MODE_ENFORCE,
        }
    }
}

const EBPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/linprov-ebpf"));

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(args.log_level.clone()),
    )
    .init();

    if matches!(args.mode, Mode::Soak | Mode::Enforce) && args.allowlist.is_none() {
        return Err(anyhow!(
            "--allowlist FILE is required in {:?} mode",
            args.mode
        ));
    }

    bump_memlock_rlimit()?;

    let mut bpf = Ebpf::load(EBPF_OBJECT).context("loading eBPF object")?;

    let btf = Btf::from_sys_fs().context("loading kernel BTF from /sys/kernel/btf/vmlinux")?;

    attach_lsm(&mut bpf, &btf, "socket_post_create")?;
    attach_lsm(&mut bpf, &btf, "file_open")?;
    attach_lsm(&mut bpf, &btf, "bprm_check_security")?;
    attach_tracepoint(&mut bpf, "sched_process_exit", "sched", "sched_process_exit")?;

    let rules = if let Some(path) = &args.allowlist {
        Rules::load(path)?
    } else {
        Rules::default()
    };
    rules.check_capacity()?;

    seed_allowlist_rules(&mut bpf, &rules)?;

    {
        let mut config_map: Array<_, u32> =
            Array::try_from(bpf.map_mut("CONFIG").context("CONFIG map missing")?)
                .context("opening CONFIG map")?;
        config_map
            .set(0, args.mode.as_u32(), 0)
            .context("setting CONFIG[0] = mode")?;
    }

    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("EVENTS map not found in eBPF object"))?;
    let ring_buf = RingBuf::try_from(events_map).context("opening ring buffer")?;
    let mut poll = AsyncFd::with_interest(RingBufFd(ring_buf), tokio::io::Interest::READABLE)?;

    let soak = match args.mode {
        Mode::Soak => {
            let path = args.allowlist.as_ref().unwrap();
            Some(Soak::open(path, args.soak.clone(), &rules)?)
        }
        _ => None,
    };

    let cfg = handler::Config { mode: args.mode, soak };

    info!(
        "linprov running ({:?}). press Ctrl-C to exit.{}",
        args.mode,
        if args.mode == Mode::Soak {
            let names: Vec<_> = args.soak.iter().map(|d| d.as_key()).collect();
            format!(" soak dims (AND-joined per emitted rule): {}", names.join(","))
        } else {
            String::new()
        }
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

fn seed_allowlist_rules(bpf: &mut Ebpf, rules: &Rules) -> Result<()> {
    let mut rule_map: Array<_, AllowRuleWire> = Array::try_from(
        bpf.map_mut("ALLOW_RULES")
            .context("ALLOW_RULES map missing")?,
    )
    .context("opening ALLOW_RULES")?;
    for (i, spec) in rules.rules.iter().enumerate() {
        let packed = AllowRuleWire(spec.pack());
        rule_map
            .set(i as u32, packed, 0)
            .with_context(|| format!("seeding rule[{i}] `{}`", spec.to_line()))?;
    }
    drop(rule_map);

    let mut count_map: Array<_, u32> = Array::try_from(
        bpf.map_mut("ALLOW_RULE_COUNT")
            .context("ALLOW_RULE_COUNT map missing")?,
    )
    .context("opening ALLOW_RULE_COUNT")?;
    let n = rules.rules.len().min(MAX_RULES) as u32;
    count_map
        .set(0, n, 0)
        .context("setting ALLOW_RULE_COUNT[0]")?;

    info!("loaded {} allowlist rules", rules.len());
    Ok(())
}

/// Newtype so we can implement `AsRawFd` for the `AsyncFd` wrapper.
struct RingBufFd(RingBuf<aya::maps::MapData>);

impl AsRawFd for RingBufFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

fn attach_lsm(bpf: &mut Ebpf, btf: &Btf, prog_name: &str) -> Result<()> {
    let program: &mut Lsm = bpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("eBPF program `{prog_name}` not present in object"))?
        .try_into()
        .with_context(|| format!("program `{prog_name}` is not an LSM program"))?;
    program
        .load(prog_name, btf)
        .with_context(|| format!("loading LSM program `{prog_name}`"))?;
    program
        .attach()
        .with_context(|| format!("attaching LSM program `{prog_name}`"))?;
    log::debug!("attached LSM hook {prog_name}");
    Ok(())
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
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
    log::debug!("attached tracepoint {prog_name} -> {category}/{name}");
    Ok(())
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!(
            "setrlimit(RLIMIT_MEMLOCK, INFINITY) failed: {}. \
             eBPF map allocation may fail on older kernels.",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

pub(crate) use Mode as ModeArg;

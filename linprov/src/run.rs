//! `linprov run` — the daemon entry. Loads the eBPF object, attaches
//! the LSM hooks + cleanup tracepoint, consumes the provenance ring
//! buffer, and (depending on mode) maintains the allowlist.

use std::{
    fs::OpenOptions,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, RingBuf},
    programs::{Lsm, TracePoint},
    Btf, Ebpf,
};
use clap::Parser;
use env_logger::Target;
use linprov_common::{AllowRule, MAX_RULES};
use log::{info, warn};
use tokio::{io::unix::AsyncFd, signal};

use crate::{
    allowlist::{Dim, Rules, Soak},
    config::{
        CliOverrides, EffectiveConfig, FileConfig, DEFAULT_ALLOWLIST_PATH, DEFAULT_CONFIG_PATH,
    },
    handler,
    hashdb::HashDb,
    inode_storage::InodeMarks,
    mode::Mode,
};

/// Newtype wrapper for `AllowRule` so we can `impl aya::Pod` locally
/// without falling foul of Rust's orphan rule (`AllowRule` lives in
/// linprov-common, which can't see aya).
#[repr(transparent)]
#[derive(Copy, Clone)]
struct AllowRuleWire(AllowRule);

unsafe impl aya::Pod for AllowRuleWire {}

const EBPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/linprov-ebpf"));

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// TOML config file. Defaults to `/etc/linprov/config.toml`; a
    /// missing file just means "use built-ins + CLI". CLI flags
    /// override file values.
    #[arg(long, env = "LINPROV_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Operating mode.
    #[arg(long, value_enum)]
    mode: Option<Mode>,

    /// Allowlist file. One rule per line; conditions AND within a
    /// line, OR across lines. Required in soak and enforce modes.
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Dimensions to bundle into each soak-emitted rule. Comma-separated.
    #[arg(long, value_delimiter = ',')]
    soak: Option<Vec<Dim>>,

    /// Also mark PIDs whose only network activity was to loopback
    /// (`127.0.0.0/8` or `::1`).
    #[arg(
        long,
        env = "LINPROV_MARK_LOCALHOST",
        value_parser = clap::builder::BoolishValueParser::new(),
        num_args = 0..=1,
        default_missing_value = "true",
    )]
    mark_localhost: Option<bool>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long)]
    log_level: Option<String>,

    /// Append logs to this file instead of stderr.
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Plaintext hash → path audit db. Maps the FNV hashes stored in
    /// records back to paths for logs, soak, and `grep`-based audit.
    #[arg(long)]
    hash_db: Option<PathBuf>,
}

pub fn execute(args: RunArgs) -> Result<()> {
    let file = FileConfig::load_or_default(&args.config)?;
    let cli = CliOverrides {
        mode: args.mode,
        allowlist: args.allowlist,
        log_file: args.log_file,
        log_level: args.log_level,
        mark_localhost: args.mark_localhost,
        soak: args.soak,
        hash_db: args.hash_db,
    };
    let cfg = EffectiveConfig::resolve(cli, file);
    init_logger(&cfg.log_level, cfg.log_file.as_deref())?;
    daemon(cfg)
}

#[tokio::main]
async fn daemon(cfg: EffectiveConfig) -> Result<()> {
    if matches!(cfg.mode, Mode::Soak | Mode::Enforce) && cfg.allowlist.is_none() {
        return Err(anyhow!(
            "{:?} mode needs an allowlist; pass --allowlist FILE, set \
             `allowlist = ...` in the config, or use the default at {}",
            cfg.mode,
            DEFAULT_ALLOWLIST_PATH
        ));
    }

    bump_memlock_rlimit()?;

    let mut bpf = Ebpf::load(EBPF_OBJECT).context("loading eBPF object")?;
    let btf = Btf::from_sys_fs().context("loading kernel BTF from /sys/kernel/btf/vmlinux")?;

    attach_lsm(&mut bpf, &btf, "socket_connect")?;
    attach_lsm(&mut bpf, &btf, "file_open")?;
    attach_lsm(&mut bpf, &btf, "bprm_check_security")?;
    attach_tracepoint(
        &mut bpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;

    let rules = if let Some(path) = &cfg.allowlist {
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
            .set(0, cfg.mode.as_u32(), 0)
            .context("setting CONFIG[0] = mode")?;
        config_map
            .set(1, u32::from(cfg.mark_localhost), 0)
            .context("setting CONFIG[1] = mark_localhost")?;
        // Index 2 = the daemon's own PID. The eBPF read-taint branch skips
        // it so the daemon — which opens marked files (O_PATH) to back-fill
        // INODE_MARKS — never taints itself and marks its own writes.
        config_map
            .set(2, std::process::id(), 0)
            .context("setting CONFIG[2] = self_pid")?;
    }

    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("EVENTS map not found in eBPF object"))?;
    let ring_buf = RingBuf::try_from(events_map).context("opening ring buffer")?;
    let mut poll = AsyncFd::with_interest(RingBufFd(ring_buf), tokio::io::Interest::READABLE)?;

    // Userspace handle to INODE_MARKS, used to back-fill the augmented record
    // (with the resolved creator_path_hash) after each file is marked. Taking
    // the map out of `bpf` keeps it live in the kernel — the attached
    // programs hold their own load-time reference.
    let inode_marks_map = bpf
        .take_map("INODE_MARKS")
        .ok_or_else(|| anyhow!("INODE_MARKS map not found in eBPF object"))?;
    let mut inode_marks = InodeMarks::new(inode_marks_map)?;

    let soak = match cfg.mode {
        Mode::Soak => {
            let path = cfg.allowlist.as_ref().unwrap();
            Some(Soak::open(path, cfg.soak.clone(), &rules)?)
        }
        _ => None,
    };

    let hashdb = HashDb::open(&cfg.hash_db)
        .with_context(|| format!("opening hash db `{}`", cfg.hash_db.display()))?;

    let handler_cfg = handler::Config {
        mode: cfg.mode,
        soak,
        hashdb: &hashdb,
    };

    info!(
        "linprov running ({:?}). press Ctrl-C to exit.{}",
        cfg.mode,
        if cfg.mode == Mode::Soak {
            let names: Vec<_> = cfg.soak.iter().map(|d| d.as_key()).collect();
            format!(
                " soak dims (AND-joined per emitted rule): {}",
                names.join(",")
            )
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
                    handler::handle_event(&handler_cfg, &mut inode_marks, item.as_ref());
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

fn init_logger(level: &str, log_file: Option<&Path>) -> Result<()> {
    let env = env_logger::Env::default().default_filter_or(level);
    let mut builder = env_logger::Builder::from_env(env);
    if let Some(path) = log_file {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening log file `{}`", path.display()))?;
        builder.target(Target::Pipe(Box::new(f)));
    }
    builder.init();
    Ok(())
}

fn seed_allowlist_rules(bpf: &mut Ebpf, rules: &Rules) -> Result<()> {
    // Two scoped borrows because `bpf.map_mut` re-borrows the Ebpf and
    // we need it for both maps.
    {
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
    }

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

fn attach_tracepoint(bpf: &mut Ebpf, prog_name: &str, category: &str, name: &str) -> Result<()> {
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

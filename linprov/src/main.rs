//! linprov userspace daemon.
//!
//! Loads the eBPF object (LSM programs + one cleanup tracepoint), attaches
//! everything, consumes the provenance event ring buffer, and (depending on
//! mode) maintains a multi-dimensional allowlist of marked binaries
//! permitted to execute.

use std::{
    os::fd::AsRawFd,
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap as AyaHashMap, RingBuf},
    programs::{Lsm, TracePoint},
    Btf, Ebpf,
};
use clap::{Parser, ValueEnum};
use linprov_common::{
    folder_hash, COMM_LEN, CREATOR_PATH_LEN, MODE_ENFORCE, MODE_OBSERVE, MODE_SOAK, PATH_LEN,
};
use log::{info, warn};
use tokio::{io::unix::AsyncFd, signal};

mod allowlist;
mod handler;

use allowlist::{comm_key, creator_path_key, path_key, Dim, Rules, Soak};

#[derive(Parser, Debug)]
#[command(
    name = "linprov",
    about = "eBPF-based mark-of-the-web provenance tracker"
)]
struct Args {
    /// Operating mode.
    #[arg(long, value_enum, default_value_t = Mode::Observe)]
    mode: Mode,

    /// Allowlist file. New format: one rule per line, either
    /// `<dim>=<value>` for any of {target_filename, target_folder,
    /// creator_process, creator_comm, creator_uid, execution_uid}, or a
    /// bare absolute path (interpreted as `target_filename`). Required
    /// in soak and enforce modes.
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Dimensions to record during soak. Comma-separated.
    /// Default: `creator_process` (recommended starting point — one rule
    /// per distinct creator binary like `creator_process=/usr/bin/curl`).
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
    /// Log and append one rule per `--soak` dimension to the allowlist
    /// file for each PROVENANCE-EXEC.
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

    seed_allowlist_maps(&mut bpf, &rules)?;

    {
        let mut config_map: Array<_, u32> = Array::try_from(
            bpf.map_mut("CONFIG").context("CONFIG map missing")?,
        )
        .context("opening CONFIG map")?;
        config_map
            .set(0, args.mode.as_u32(), 0)
            .context("setting CONFIG[0] = mode")?;
    }

    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("EVENTS map not found in eBPF object"))?;
    let ring_buf = RingBuf::try_from(events_map).context("opening ring buffer")?;
    let mut poll =
        AsyncFd::with_interest(RingBufFd(ring_buf), tokio::io::Interest::READABLE)?;

    let soak = match args.mode {
        Mode::Soak => {
            let path = args.allowlist.as_ref().unwrap();
            Some(Soak::open(path, args.soak.clone(), &rules)?)
        }
        _ => None,
    };

    let cfg = handler::Config {
        mode: args.mode,
        soak,
    };

    info!(
        "linprov running ({:?}). press Ctrl-C to exit.{}",
        args.mode,
        if args.mode == Mode::Soak {
            let names: Vec<_> = args.soak.iter().map(|d| d.as_key()).collect();
            format!(" soak dimensions: {}", names.join(","))
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

fn seed_allowlist_maps(bpf: &mut Ebpf, rules: &Rules) -> Result<()> {
    {
        let mut map: AyaHashMap<_, [u8; PATH_LEN], u8> = AyaHashMap::try_from(
            bpf.map_mut("ALLOW_TARGET_FILENAMES")
                .context("ALLOW_TARGET_FILENAMES map missing")?,
        )
        .context("opening ALLOW_TARGET_FILENAMES")?;
        for v in &rules.target_filenames {
            map.insert(path_key(v), 1u8, 0)
                .with_context(|| format!("seeding target_filename `{v}`"))?;
        }
    }
    {
        let mut map: AyaHashMap<_, u64, u8> = AyaHashMap::try_from(
            bpf.map_mut("ALLOW_TARGET_FOLDERS")
                .context("ALLOW_TARGET_FOLDERS map missing")?,
        )
        .context("opening ALLOW_TARGET_FOLDERS")?;
        for v in &rules.target_folders {
            // FNV-1a hash of the rule, computed identically on both
            // sides. The BPF folder walk does the same hash as it scans
            // the executed path; equal prefix → equal hash → map hit.
            let h = folder_hash(v);
            map.insert(&h, 1u8, 0)
                .with_context(|| format!("seeding target_folder `{v}` (hash={h:#x})"))?;
        }
    }
    {
        let mut map: AyaHashMap<_, [u8; CREATOR_PATH_LEN], u8> = AyaHashMap::try_from(
            bpf.map_mut("ALLOW_CREATOR_PROCESSES")
                .context("ALLOW_CREATOR_PROCESSES map missing")?,
        )
        .context("opening ALLOW_CREATOR_PROCESSES")?;
        for v in &rules.creator_processes {
            map.insert(creator_path_key(v), 1u8, 0)
                .with_context(|| format!("seeding creator_process `{v}`"))?;
        }
    }
    {
        let mut map: AyaHashMap<_, [u8; COMM_LEN], u8> = AyaHashMap::try_from(
            bpf.map_mut("ALLOW_CREATOR_COMMS")
                .context("ALLOW_CREATOR_COMMS map missing")?,
        )
        .context("opening ALLOW_CREATOR_COMMS")?;
        for v in &rules.creator_comms {
            map.insert(comm_key(v), 1u8, 0)
                .with_context(|| format!("seeding creator_comm `{v}`"))?;
        }
    }
    {
        let mut map: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
            bpf.map_mut("ALLOW_CREATOR_UIDS")
                .context("ALLOW_CREATOR_UIDS map missing")?,
        )
        .context("opening ALLOW_CREATOR_UIDS")?;
        for v in &rules.creator_uids {
            map.insert(v, 1u8, 0)
                .with_context(|| format!("seeding creator_uid `{v}`"))?;
        }
    }
    {
        let mut map: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
            bpf.map_mut("ALLOW_EXECUTION_UIDS")
                .context("ALLOW_EXECUTION_UIDS map missing")?,
        )
        .context("opening ALLOW_EXECUTION_UIDS")?;
        for v in &rules.execution_uids {
            map.insert(v, 1u8, 0)
                .with_context(|| format!("seeding execution_uid `{v}`"))?;
        }
    }
    info!(
        "loaded {} allowlist rules (target_filename={} target_folder={} \
         creator_process={} creator_comm={} creator_uid={} execution_uid={})",
        rules.total_len(),
        rules.target_filenames.len(),
        rules.target_folders.len(),
        rules.creator_processes.len(),
        rules.creator_comms.len(),
        rules.creator_uids.len(),
        rules.execution_uids.len(),
    );
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

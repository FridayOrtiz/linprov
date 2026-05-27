//! linprov userspace daemon.
//!
//! Loads the eBPF object (LSM programs + one cleanup tracepoint), attaches
//! everything, consumes the provenance event ring buffer, and (depending on
//! mode) maintains an allowlist of marked binaries permitted to execute.

use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap as AyaHashMap, RingBuf},
    programs::{Lsm, TracePoint},
    Btf, Ebpf,
};
use clap::{Parser, ValueEnum};
use linprov_common::{MODE_ENFORCE, MODE_OBSERVE, MODE_SOAK, PATH_LEN};
use log::{info, warn};
use tokio::{io::unix::AsyncFd, signal};

mod handler;

#[derive(Parser, Debug)]
#[command(
    name = "linprov",
    about = "eBPF-based mark-of-the-web provenance tracker"
)]
struct Args {
    /// Operating mode.
    #[arg(long, value_enum, default_value_t = Mode::Observe)]
    mode: Mode,

    /// Allowlist file: one absolute path per line, `#` for comments. Required
    /// for soak and enforce modes; ignored in observe.
    #[arg(long)]
    allowlist: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum Mode {
    /// Log only; nothing enforced or recorded persistently.
    Observe,
    /// Log and append every PROVENANCE-EXEC path to the allowlist file.
    /// Lets you generate the allowlist by running the system normally.
    Soak,
    /// Block execve of marked files not on the allowlist (-EPERM from
    /// security_bprm_check).
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

    let allowlist = if let Some(path) = &args.allowlist {
        read_allowlist_file(path)?
    } else {
        HashSet::new()
    };

    {
        let mut allow_map: AyaHashMap<_, [u8; PATH_LEN], u8> =
            AyaHashMap::try_from(bpf.map_mut("ALLOWLIST").context("ALLOWLIST map missing")?)
                .context("opening ALLOWLIST map")?;
        for path in &allowlist {
            let key = path_key(path);
            allow_map
                .insert(&key, 1u8, 0)
                .with_context(|| format!("seeding allowlist with `{path}`"))?;
        }
        info!("loaded {} allowlist entries", allowlist.len());
    }

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

    let allowlist_writer = match args.mode {
        Mode::Soak => {
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(args.allowlist.as_ref().unwrap())
                .with_context(|| {
                    format!("opening allowlist `{}` for soak append", args.allowlist.as_ref().unwrap().display())
                })?;
            Some(Mutex::new(f))
        }
        _ => None,
    };

    let cfg = handler::Config {
        mode: args.mode,
        seen: Mutex::new(allowlist),
        allowlist_writer,
    };

    info!("linprov running ({:?}). press Ctrl-C to exit.", args.mode);

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

/// Encode a path the way the eBPF program leaves it in the filename buffer
/// after `bpf_d_path`. The kernel helper:
///   1. Calls `d_path` which writes "<path>\0" right-aligned into the buffer.
///   2. memmoves the resulting string (path + NUL, length `n+1`) to the
///      front of the buffer, leaving the original right-aligned copy intact.
/// So the buffer ends up with the path at byte 0..=n (NUL terminator at n)
/// *and* a second copy of path-plus-NUL right-aligned at the tail. We have
/// to mirror that exactly or the hash-map key won't match.
pub(crate) fn path_key(p: &str) -> [u8; PATH_LEN] {
    let mut key = [0u8; PATH_LEN];
    let bytes = p.as_bytes();
    let n = bytes.len().min(PATH_LEN - 1); // leave room for the NUL
    if n == 0 {
        return key;
    }
    key[..n].copy_from_slice(&bytes[..n]);
    // `n+1` bytes of "<path>\0" right-aligned at the tail. The NUL byte is
    // already zero from the array init; we just need the path bytes.
    let tail_path_start = PATH_LEN - 1 - n;
    key[tail_path_start..tail_path_start + n].copy_from_slice(&bytes[..n]);
    key
}

fn read_allowlist_file(path: &Path) -> Result<HashSet<String>> {
    let mut set = HashSet::new();
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("allowlist `{}` doesn't exist yet — starting empty", path.display());
            return Ok(set);
        }
        Err(e) => return Err(anyhow!("opening allowlist `{}`: {e}", path.display())),
    };
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.with_context(|| format!("reading line {} of allowlist", i + 1))?;
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        set.insert(trimmed.to_string());
    }
    Ok(set)
}

pub(crate) fn append_allowlist(writer: &Mutex<File>, path: &str) -> std::io::Result<()> {
    let mut f = writer.lock().expect("allowlist file mutex poisoned");
    writeln!(f, "{path}")?;
    f.sync_data()?;
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

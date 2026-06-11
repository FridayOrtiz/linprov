//! `linprov run` — the daemon entry. Loads the eBPF object, attaches
//! the LSM hooks + cleanup tracepoint, consumes the provenance ring
//! buffer, and (depending on mode) maintains the allowlist.

use std::{
    fs::{self, OpenOptions},
    os::fd::AsRawFd,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, RingBuf},
    programs::{Lsm, TracePoint},
    Btf, Ebpf,
};
use clap::Parser;
use env_logger::Target;
use linprov_common::{fnv_hash_bytes, AllowRule, COMM_LEN, MAX_RULES};
use log::{info, warn};
use tokio::{
    io::{unix::AsyncFd, AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    signal,
    signal::unix::{signal as unix_signal, SignalKind},
    sync::broadcast,
};

use crate::{
    allowlist::{Dim, RuleSpec, Rules, Soak},
    config::{
        CliOverrides, EffectiveConfig, FileConfig, NotifyMode, DEFAULT_ALLOWLIST_PATH,
        DEFAULT_CONFIG_PATH, DEFAULT_CONTROL_SOCKET_PATH,
    },
    control::{BlockEvent, Control},
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

    /// Script interpreters (by `comm`) whose reads of a marked file are
    /// enforced like an execve, so `bash foo.sh` / `python foo.py` /
    /// `. foo.sh` honor the same policy as `./foo.sh`. Comma-separated;
    /// pass an empty value to disable script enforcement. Defaults to a
    /// built-in set (bash, sh, python, perl, node, …).
    #[arg(long, value_delimiter = ',')]
    interpreters: Option<Vec<String>>,

    /// `off` (default) keeps the control socket root-only; `tray` exposes
    /// it to the `linprov` group (socket 0660) so a user-session
    /// `linprov notify` tray agent can subscribe to blocks and apply
    /// allows.
    #[arg(long, value_enum)]
    notifications: Option<NotifyMode>,
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
        interpreters: args.interpreters,
        notifications: args.notifications,
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
    // Over-capacity is a warning, not a fatal error (handled in seed_rules):
    // the first MAX_RULES load and the rest are ignored. A long soak run can
    // grow the file past the ceiling; the daemon must still start (and keep
    // enforcing what fits) rather than crash-loop.
    seed_rules(&mut bpf, &rules.rules)?;
    seed_interpreters(&mut bpf, &cfg.interpreters)?;

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

    // Rule-mutation state: the in-memory transient (`allow --once`) rules
    // and the recent-blocks token table. The BPF map is reseeded from
    // `control.combined()` = file rules ∪ transient on every live change.
    let mut control = Control::new(cfg.allowlist.clone());

    // Block events fan out to control-socket `subscribe`rs (the tray
    // agent). A bounded channel; if a slow subscriber lags it loses old
    // events (RecvError::Lagged) rather than back-pressuring the daemon.
    let (block_tx, _) = broadcast::channel::<BlockEvent>(256);

    // SIGHUP → reload the allowlist file and re-seed the BPF rules map,
    // without restarting the daemon or re-attaching the LSM hooks. Lets an
    // operator edit `list.allow` (or `linprov allow`) and apply it live.
    // Only the allowlist is reloaded — mode, interpreters, and other launch
    // config stay as started.
    let mut sighup = unix_signal(SignalKind::hangup()).context("installing SIGHUP handler")?;

    // Control socket for `linprov allow [--once] <token>`. Best-effort: if
    // we can't bind (e.g. /run not writable), log and run without it rather
    // than fail to start — enforcement doesn't depend on it.
    let listener = match bind_control_socket(Path::new(DEFAULT_CONTROL_SOCKET_PATH), cfg.notifications)
    {
        Ok(l) => {
            info!(
                "control socket listening at {DEFAULT_CONTROL_SOCKET_PATH} (notifications={:?})",
                cfg.notifications
            );
            Some(l)
        }
        Err(e) => {
            warn!("control socket disabled ({DEFAULT_CONTROL_SOCKET_PATH}): {e:#}");
            None
        }
    };

    info!(
        "linprov running ({:?}). press Ctrl-C to exit, SIGHUP to reload the allowlist.{}",
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

            _ = sighup.recv() => {
                info!(
                    "SIGHUP received — reloading allowlist from {}",
                    cfg.allowlist
                        .as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string())
                );
                // Reseed from file ∪ transient. On failure (unreadable file)
                // the helper errors before writing the map, so the currently
                // active rules keep enforcing. In-memory transient rules are
                // preserved across the reload.
                if let Err(e) = reseed_from_control(&mut bpf, &control) {
                    warn!("allowlist reload failed, keeping current rules: {e:#}");
                }
            }

            // `linprov allow` connection. `accept_opt` resolves to a pending
            // future when the socket is disabled, so the branch never fires.
            conn = accept_opt(listener.as_ref()) => {
                match conn {
                    Ok((stream, _)) => {
                        handle_control_conn(stream, &mut control, &mut bpf, &block_tx).await;
                    }
                    Err(e) => warn!("control socket accept failed: {e}"),
                }
            }

            res = poll.readable_mut() => {
                let mut guard = res.context("polling ring buffer")?;
                let ring = &mut guard.get_inner_mut().0;
                while let Some(item) = ring.next() {
                    handler::handle_event(
                        &handler_cfg,
                        &mut inode_marks,
                        &mut control.blocks,
                        &block_tx,
                        item.as_ref(),
                    );
                }
                guard.clear_ready();
            }
        }
    }

    // Best-effort: drop the socket file so a future daemon binds cleanly.
    let _ = fs::remove_file(DEFAULT_CONTROL_SOCKET_PATH);
    Ok(())
}

/// Accept on the control socket if enabled; otherwise never resolve (so the
/// `select!` branch stays dormant when the socket failed to bind).
async fn accept_opt(
    listener: Option<&UnixListener>,
) -> std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)> {
    match listener {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

/// Create `/run/linprov`, remove any stale socket, and bind.
///
/// In `Off` mode both the dir and socket are root-only (0700 / 0600). In
/// `Tray` mode they're chowned to the `linprov` group and group-accessible
/// (dir 0750, socket 0660) so a user-session `linprov notify` agent can
/// connect — crucially the *directory* needs group search/`x`, since a
/// 0660 socket inside a 0700 dir is unreachable. If the group doesn't
/// exist we warn and stay root-only rather than fail to start.
fn bind_control_socket(path: &Path, notify: NotifyMode) -> Result<UnixListener> {
    let gid = if notify == NotifyMode::Tray {
        match linprov_group_gid() {
            Some(g) => Some(g),
            None => {
                warn!(
                    "notifications=tray but no `linprov` group found; keeping the \
                     control socket root-only (create the group and add your user, \
                     then restart). See README."
                );
                None
            }
        }
    } else {
        None
    };

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let dir_mode = if let Some(g) = gid {
            std::os::unix::fs::chown(dir, None, Some(g))
                .with_context(|| format!("chown {} to group linprov", dir.display()))?;
            0o750 // group can traverse to reach the socket
        } else {
            0o700
        };
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(dir_mode));
    }

    let _ = fs::remove_file(path); // clear a stale socket from a prior run
    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;

    let sock_mode = if let Some(g) = gid {
        std::os::unix::fs::chown(path, None, Some(g))
            .with_context(|| format!("chown {} to group linprov", path.display()))?;
        0o660
    } else {
        0o600
    };
    fs::set_permissions(path, fs::Permissions::from_mode(sock_mode))
        .with_context(|| format!("chmod {sock_mode:o} {}", path.display()))?;
    Ok(listener)
}

/// gid of the `linprov` group, or `None` if it doesn't exist.
fn linprov_group_gid() -> Option<u32> {
    // SAFETY: getgrnam returns a pointer into a static buffer; we read the
    // gid before any further libc call could clobber it.
    let name = std::ffi::CString::new("linprov").ok()?;
    let grp = unsafe { libc::getgrnam(name.as_ptr()) };
    if grp.is_null() {
        None
    } else {
        Some(unsafe { (*grp).gr_gid })
    }
}

/// Serve one control request. `allow`/`once <token>` apply a rule inline
/// and reply `OK <rule>` / `ERR <msg>`. `subscribe` upgrades the
/// connection to a long-lived block-event stream (handled in a spawned
/// task holding a broadcast receiver — it needs neither `Control` nor the
/// `Ebpf`, so it doesn't pin the daemon's borrows). The initial verb read
/// has a timeout so a stuck client can't wedge the loop.
async fn handle_control_conn(
    mut stream: tokio::net::UnixStream,
    control: &mut Control,
    bpf: &mut Ebpf,
    block_tx: &broadcast::Sender<BlockEvent>,
) {
    let mut buf = vec![0u8; 4096];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await;
    let n = match read {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!("control read failed: {e}");
            return;
        }
        Err(_) => {
            let _ = stream.write_all(b"ERR read timed out\n").await;
            return;
        }
    };
    let req = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    if req == "subscribe" {
        let rx = block_tx.subscribe();
        tokio::spawn(stream_blocks(stream, rx));
        return;
    }

    let reply = match process_control_request(&req, control, bpf) {
        Ok(rule) => format!("OK {rule}\n"),
        Err(e) => format!("ERR {e:#}\n"),
    };
    let _ = stream.write_all(reply.as_bytes()).await;
}

/// Stream block events to a `subscribe`d client until it disconnects.
/// Writes each event's one-line wire form; a write error (peer gone) ends
/// the task. On `Lagged` (a slow client) we skip dropped events and keep
/// going; `Closed` (daemon shutting down) ends it.
async fn stream_blocks(
    mut stream: tokio::net::UnixStream,
    mut rx: broadcast::Receiver<BlockEvent>,
) {
    let _ = stream.write_all(b"OK subscribed\n").await;
    loop {
        match rx.recv().await {
            Ok(ev) => {
                let line = format!("{}\n", ev.to_wire());
                if stream.write_all(line.as_bytes()).await.is_err() {
                    break; // subscriber went away
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Parse and apply one control request line. `allow <token>` persists to
/// the allowlist file; `once <token>` adds an in-memory transient rule.
/// Both reseed the BPF map from `control.combined()`.
fn process_control_request(req: &str, control: &mut Control, bpf: &mut Ebpf) -> Result<String> {
    let mut parts = req.split_whitespace();
    let (verb, token) = (parts.next(), parts.next());
    let once = match verb {
        Some("once") => true,
        Some("allow") => false,
        _ => return Err(anyhow!("bad request `{req}` (expected `allow|once <token>`)")),
    };
    let token = token.ok_or_else(|| anyhow!("missing token"))?;
    let rule = control.apply(token, once)?;
    reseed_from_control(bpf, control)?;
    info!(
        "allow{} applied (token {token}): {rule}",
        if once { " --once" } else { "" }
    );
    Ok(rule)
}

/// Reseed the BPF rules map from `control.combined()` (file ∪ transient).
/// Over-capacity warns and truncates (same as startup); a file read error
/// propagates without touching the map.
fn reseed_from_control(bpf: &mut Ebpf, control: &Control) -> Result<()> {
    let rules = control.combined()?;
    seed_rules(bpf, &rules)
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

/// Seed the BPF `ALLOW_RULES` / `ALLOW_RULE_COUNT` maps from `rules` (the
/// combined file ∪ transient set). Over-capacity is a warning, not an
/// error: the first `MAX_RULES` are written and the rest ignored, so a
/// daemon never crash-loops on a too-big allowlist. The BPF side reads
/// exactly `ALLOW_RULE_COUNT` slots, so a shrunk set leaves stale tail
/// slots simply unread — no O(MAX_RULES) clear needed.
fn seed_rules(bpf: &mut Ebpf, rules: &[RuleSpec]) -> Result<()> {
    let total = rules.len();
    let n = total.min(MAX_RULES);
    if total > MAX_RULES {
        warn!("{total} allowlist rules exceeds the BPF map capacity ({MAX_RULES}); applying the first {n}");
    }
    {
        let mut rule_map: Array<_, AllowRuleWire> = Array::try_from(
            bpf.map_mut("ALLOW_RULES")
                .context("ALLOW_RULES map missing")?,
        )
        .context("opening ALLOW_RULES")?;
        for (i, spec) in rules.iter().take(n).enumerate() {
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
    count_map
        .set(0, n as u32, 0)
        .context("setting ALLOW_RULE_COUNT[0]")?;

    // "{n} of {total}" makes capping visible: equal when it fits.
    info!("loaded {n} of {total} allowlist rules");
    Ok(())
}

/// Seed the `INTERPRETERS` BPF map from the configured interpreter list.
/// Each name is hashed with the same FNV-1a-64 the eBPF `fnv_comm` uses,
/// over the bytes the kernel would keep in `comm` (truncated to
/// `COMM_LEN - 1`). An empty list leaves the map empty, which disables
/// script enforcement in the read branch.
fn seed_interpreters(bpf: &mut Ebpf, interpreters: &[String]) -> Result<()> {
    let mut map: HashMap<_, u64, u8> = HashMap::try_from(
        bpf.map_mut("INTERPRETERS")
            .context("INTERPRETERS map missing")?,
    )
    .context("opening INTERPRETERS")?;

    let mut n = 0u32;
    for name in interpreters {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let bytes = name.as_bytes();
        let truncated = &bytes[..bytes.len().min(COMM_LEN - 1)];
        let h = fnv_hash_bytes(truncated);
        map.insert(h, 1u8, 0)
            .with_context(|| format!("seeding interpreter `{name}`"))?;
        n += 1;
    }

    if n == 0 {
        info!("script enforcement disabled (no interpreters configured)");
    } else {
        info!("script enforcement on for {n} interpreters: {}", interpreters.join(","));
    }
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

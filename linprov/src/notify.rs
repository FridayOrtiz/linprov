//! `linprov notify` — a user-session tray agent for interactive approvals.
//!
//! The daemon runs as root on the system bus and can't reach the user's
//! session bus where the tray/notifier live, so this agent bridges them.
//! It connects to the daemon's control socket (group `linprov`, exposed by
//! `notifications = "tray"`), `subscribe`s to block events, and presents a
//! StatusNotifierItem tray icon (via `ksni`) whose context menu lists
//! recent blocked execs — each with **Allow once / Allow always / Quarantine
//! / Dismiss**. Left-clicking the icon opens the `linprov review` window: a
//! multi-select checkbox list with the same four bulk actions and
//! per-component (dimension) selection. A buttonless desktop notification
//! also fires per block as an alert.
//!
//! Menu clicks drive the control-socket verbs (`allow` / `once` /
//! `quarantine` / `dismiss <token>`); a `RESOLVED` broadcast keeps the menu
//! in sync when another client (the window, `linprov allow`) actions a block.
//! Run it from your sway config (`exec linprov notify`); needs a
//! StatusNotifierHost (e.g. waybar's tray).

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::mpsc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ksni::blocking::TrayMethods;
use log::{info, warn};

use crate::config::DEFAULT_CONTROL_SOCKET_PATH;
use crate::quarantine::TAMPER_MARKER;

#[derive(Parser, Debug)]
pub struct NotifyArgs {
    /// Daemon control socket to connect to.
    #[arg(long, default_value = DEFAULT_CONTROL_SOCKET_PATH)]
    socket: PathBuf,
}

/// Most-recent-first cap on tray entries.
const MAX_RECENT: usize = 20;

/// The custom tray icon, embedded so the agent is self-contained (no
/// hicolor-theme install needed). "Mark of the web": an amber spider-web
/// with a marked node — calm white when idle, alarm red when a block is
/// pending. Rendered from `assets/linprov*.svg`.
const ICON_IDLE_PNG: &[u8] = include_bytes!("../assets/linprov-64.png");
const ICON_ATTN_PNG: &[u8] = include_bytes!("../assets/linprov-attention-64.png");

/// Decode an RGBA8 PNG into a ksni tray `Icon` (ARGB32, network byte
/// order, as the StatusNotifierItem spec wants). Returns `None` (→ the
/// host falls back to `icon_name`) if the PNG isn't RGBA8.
fn load_icon(png_bytes: &[u8]) -> Option<ksni::Icon> {
    let mut reader = png::Decoder::new(png_bytes).read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    let mut data = Vec::with_capacity(buf.len());
    for px in buf[..info.buffer_size()].chunks_exact(4) {
        data.extend_from_slice(&[px[3], px[0], px[1], px[2]]); // RGBA → ARGB
    }
    Some(ksni::Icon {
        width: info.width as i32,
        height: info.height as i32,
        data,
    })
}

#[derive(Debug, Clone)]
struct RecentBlock {
    token: String,
    kind: String,
    target: String,
    creator: String,
}

#[derive(Debug, Clone, Copy)]
enum ActionKind {
    Once,
    Always,
    Quarantine,
    Dismiss,
}

/// A menu click, handed from the tray thread to the action worker.
#[derive(Debug)]
struct Action {
    kind: ActionKind,
    token: String,
    target: String,
}

#[derive(Debug)]
struct LinprovTray {
    recent: Vec<RecentBlock>,
    tx: mpsc::Sender<Action>,
    /// Control socket path, passed to the `linprov review` window launched on
    /// left-click.
    socket: PathBuf,
    /// Whether the subscribe stream to the daemon is currently up. Surfaced
    /// in the tooltip so an empty tray distinguishes "no pending blocks" from
    /// "can't reach the daemon" (e.g. linprov.service not running).
    connected: bool,
}

impl LinprovTray {
    fn push(&mut self, b: RecentBlock) {
        self.recent.retain(|x| x.token != b.token); // de-dup repeats
        self.recent.insert(0, b);
        self.recent.truncate(MAX_RECENT);
    }

    /// A menu item was clicked: drop the entry from the tray and hand the
    /// (blocking) socket call to the worker thread.
    fn dispatch(&mut self, kind: ActionKind, token: &str) {
        if let Some(b) = self.recent.iter().find(|x| x.token == token).cloned() {
            let _ = self.tx.send(Action {
                kind,
                token: token.to_string(),
                target: b.target,
            });
        }
        self.recent.retain(|x| x.token != token);
    }

    /// Spawn the `linprov review` window as a separate process (its egui event
    /// loop can't share this thread with ksni). Best-effort; the caller falls
    /// back to a notification if it can't launch.
    fn launch_review(&self) -> Result<()> {
        // The child inherits *our* environment. A `systemd --user` tray snapshots
        // the user manager's env at spawn time; if the compositor imported
        // WAYLAND_DISPLAY *after* this agent started, neither WAYLAND_DISPLAY nor
        // DISPLAY is set here, and the spawned `linprov review` aborts in winit
        // ("neither WAYLAND_DISPLAY nor WAYLAND_SOCKET nor DISPLAY is set") before
        // any window appears. `spawn()` succeeds regardless (the child starts,
        // then dies), so without this check the failure is completely silent.
        // Detect it up front so the caller shows the fallback notification.
        if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
            return Err(anyhow!(
                "no WAYLAND_DISPLAY/DISPLAY in the tray agent's environment, so the \
                 review window can't open. Import it into the systemd user manager \
                 and restart the agent: `systemctl --user import-environment \
                 WAYLAND_DISPLAY DISPLAY && systemctl --user restart \
                 linprov-notify.service`."
            ));
        }
        let exe = std::env::current_exe().context("locating the linprov binary")?;
        std::process::Command::new(exe)
            .arg("review")
            .arg("--socket")
            .arg(&self.socket)
            .spawn()
            .context("launching `linprov review`")?;
        Ok(())
    }
}

impl ksni::Tray for LinprovTray {
    fn id(&self) -> String {
        "linprov".into()
    }
    fn title(&self) -> String {
        "linprov".into()
    }
    /// Left-click (`Activate`) opens the multi-select review window — a
    /// checkbox list of pending blocks with bulk Allow once / Allow always /
    /// Quarantine / Dismiss and per-component selection. It runs as its own
    /// process (its egui loop can't share this ksni thread). If it can't
    /// launch (built without the `review-ui` feature, or no `current_exe`),
    /// fall back to the old informational notification pointing at the
    /// right-click menu (which is otherwise undiscoverable).
    fn activate(&mut self, _x: i32, _y: i32) {
        if let Err(e) = self.launch_review() {
            let body = if self.recent.is_empty() {
                "No pending blocks.".to_string()
            } else {
                let n = self.recent.len();
                let s = if n == 1 { "" } else { "s" };
                format!(
                    "{n} pending decision{s}. Right-click this icon for \
                     Allow / Quarantine / Dismiss.\n(review window unavailable: {e})"
                )
            };
            let icon = if self.recent.is_empty() {
                "security-high"
            } else {
                "security-low"
            };
            let _ = notify_rust::Notification::new()
                .summary("linprov")
                .body(&body)
                .icon(icon)
                .show();
        }
    }
    fn icon_name(&self) -> String {
        // Intentionally empty: a non-empty themed name (e.g. "security-high")
        // wins over `icon_pixmap` in most StatusNotifierHosts (waybar) and
        // renders the *theme's* generic icon — a shield — not ours. Leaving
        // it blank forces the host to use the embedded spider-web pixmap.
        String::new()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        // Calm web when idle; red-node web when blocks are pending.
        let png = if self.recent.is_empty() {
            ICON_IDLE_PNG
        } else {
            ICON_ATTN_PNG
        };
        load_icon(png).into_iter().collect()
    }
    /// The SNI-standard "look at me" signal: hosts emphasize NeedsAttention
    /// items (waybar tags them `.needs-attention` for styling), and may swap
    /// in `attention_icon_pixmap`. This is what was missing — a bare pixmap
    /// swap is too subtle and waybar doesn't reliably re-fetch it.
    fn status(&self) -> ksni::Status {
        if self.recent.is_empty() {
            ksni::Status::Active
        } else {
            ksni::Status::NeedsAttention
        }
    }
    fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
        load_icon(ICON_ATTN_PNG).into_iter().collect()
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        let description = if !self.connected {
            "not connected to the linprov daemon (is linprov.service running \
             with notifications = \"tray\"?)"
                .to_string()
        } else if self.recent.is_empty() {
            "no pending blocks".to_string()
        } else {
            let n = self.recent.len();
            let s = if n == 1 { "" } else { "s" };
            format!("{n} pending decision{s} — right-click the icon to allow or dismiss")
        };
        ksni::ToolTip {
            title: "linprov".to_string(),
            description,
            ..Default::default()
        }
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let mut items: Vec<ksni::MenuItem<Self>> = Vec::new();

        if self.recent.is_empty() {
            items.push(
                StandardItem {
                    label: "No recent blocks".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        } else {
            for b in &self.recent {
                let label = format!("{} · {}", basename(&b.target), b.creator);
                let (t_once, t_always, t_quar, t_dismiss) = (
                    b.token.clone(),
                    b.token.clone(),
                    b.token.clone(),
                    b.token.clone(),
                );
                items.push(
                    SubMenu {
                        label,
                        submenu: vec![
                            StandardItem {
                                label: "Allow once".into(),
                                activate: Box::new(move |t: &mut Self| {
                                    t.dispatch(ActionKind::Once, &t_once)
                                }),
                                ..Default::default()
                            }
                            .into(),
                            StandardItem {
                                label: "Allow always".into(),
                                activate: Box::new(move |t: &mut Self| {
                                    t.dispatch(ActionKind::Always, &t_always)
                                }),
                                ..Default::default()
                            }
                            .into(),
                            StandardItem {
                                label: "Quarantine".into(),
                                activate: Box::new(move |t: &mut Self| {
                                    t.dispatch(ActionKind::Quarantine, &t_quar)
                                }),
                                ..Default::default()
                            }
                            .into(),
                            StandardItem {
                                label: "Dismiss".into(),
                                activate: Box::new(move |t: &mut Self| {
                                    t.dispatch(ActionKind::Dismiss, &t_dismiss)
                                }),
                                ..Default::default()
                            }
                            .into(),
                        ],
                        ..Default::default()
                    }
                    .into(),
                );
            }
        }

        items.push(ksni::MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Quit linprov tray".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}

pub fn run(args: NotifyArgs) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Action>();

    // One-shot preflight (before the tray even registers, so it fires even on
    // a host with no tray yet): a frequent silent failure is the agent running
    // without the `linprov` group even though the *user* is a member — the
    // classic stale-launcher case (a `systemd --user` service inherits the
    // user manager's groups, which only refresh on a full re-login). Call it
    // out once so the empty tray has an explanation, not just the per-retry
    // EPERM warnings (whose generic "are you in the group?" hint misleads).
    if lacks_linprov_group() {
        warn!(
            "this process is NOT in the `linprov` group, so it can't reach the \
             daemon's control socket — the tray will stay empty. If `id -nG` \
             shows you in the group, your launcher has a stale group set: a \
             `systemd --user` service inherits the user manager's groups, which \
             only refresh after a FULL logout/login or reboot (not \
             `systemctl --user restart`/`daemon-reexec`/`newgrp`)."
        );
    }

    // Register the tray, retrying with backoff. Launched from a session
    // startup hook (sway `exec linprov notify`), this can fire before the
    // StatusNotifierHost (waybar's tray) is up — exiting on that race is
    // why the icon never appeared. Keep trying so the agent survives a
    // cold start and the icon lands once the host is ready.
    let mut backoff = Duration::from_millis(500);
    let handle = loop {
        let tray = LinprovTray {
            recent: Vec::new(),
            tx: tx.clone(),
            socket: args.socket.clone(),
            connected: false,
        };
        match tray.spawn() {
            Ok(h) => break h,
            Err(e) => {
                warn!(
                    "tray registration failed ({e}); is a StatusNotifierHost \
                     running (e.g. waybar's tray module)? retrying in {:.0}s",
                    backoff.as_secs_f32()
                );
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    };

    // Worker: applies menu clicks against the control socket.
    let worker_socket = args.socket.clone();
    std::thread::spawn(move || action_worker(rx, worker_socket));

    info!(
        "linprov tray agent started; subscribing to {}",
        args.socket.display()
    );
    // This thread owns the subscribe stream (reconnects forever).
    subscribe_loop(&args.socket, &handle);
    Ok(())
}

/// `true` if the `linprov` group exists but *this* process isn't in it —
/// the condition behind a permission-denied on the control socket that the
/// generic "are you in the group?" hint misreads (the user often *is* a
/// member; it's the running process that isn't).
fn lacks_linprov_group() -> bool {
    let Some(gid) = linprov_gid() else {
        return false; // no group at all — a different (handled) failure
    };
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Groups:") {
            return !rest.split_whitespace().any(|g| g.parse::<u32>() == Ok(gid));
        }
    }
    false
}

/// gid of the `linprov` group, or `None` if it doesn't exist.
fn linprov_gid() -> Option<u32> {
    let name = std::ffi::CString::new("linprov").ok()?;
    // Reentrant `getgrnam_r`, not `getgrnam`: the tray runs ksni + a tokio
    // runtime (multiple threads), and the non-`_r` variant returns a pointer
    // into a process-wide static buffer a concurrent NSS call on another thread
    // could clobber. `_r` writes into our own stack buffer instead.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = [0_i8; 16384];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: `name` is a valid NUL-terminated C string; `grp`/`buf` are owned
    // local storage of the sizes passed; `result` receives a pointer into
    // `grp` (or stays null). getgrnam_r writes nothing on miss/error.
    let ret = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if ret != 0 || result.is_null() {
        return None;
    }
    Some(grp.gr_gid)
}

/// Connect, `subscribe`, and feed block events to the tray + notifications;
/// reconnect with a fixed backoff if the daemon goes away or restarts.
fn subscribe_loop(socket: &Path, handle: &ksni::blocking::Handle<LinprovTray>) {
    loop {
        if let Err(e) = subscribe_once(socket, handle) {
            warn!("control socket: {e:#}");
        }
        // subscribe_once only returns on disconnect/failure — reflect that in
        // the tray (tooltip → "not connected") so a down daemon is visible.
        handle.update(|t: &mut LinprovTray| t.connected = false);
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn subscribe_once(socket: &Path, handle: &ksni::blocking::Handle<LinprovTray>) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {} (is the daemon running with notifications=tray, and are you in the linprov group?)", socket.display()))?;
    stream
        .write_all(b"subscribe\n")
        .context("sending subscribe")?;
    handle.update(|t: &mut LinprovTray| t.connected = true);

    // Backfill the current pending set: the subscribe stream only carries
    // *future* events, so without this a freshly-(re)started tray shows an
    // empty menu even when blocks are pending. `push`'s de-dup absorbs any
    // overlap with events buffered on the stream meanwhile.
    if let Ok(blocks) = list_pending(socket) {
        for b in blocks {
            handle.update(move |t: &mut LinprovTray| t.push(b));
        }
    }

    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line.context("reading block stream")?;
        // `RESOLVED\t<token>` — the block was allowed/quarantined/dismissed by
        // some client (this tray, the review window, or `linprov allow`); drop
        // it so every view stays in sync.
        if let Some(token) = line.strip_prefix("RESOLVED\t") {
            let token = token.to_string();
            handle.update(move |t: &mut LinprovTray| t.recent.retain(|x| x.token != token));
        } else if let Some(b) = parse_block(&line) {
            notify_block(&b);
            let b2 = b.clone();
            handle.update(move |t: &mut LinprovTray| t.push(b2));
        }
    }
    Err(anyhow!("subscribe stream closed"))
}

/// One-shot `list` of the daemon's pending blocks, for backfilling the tray
/// menu on (re)connect. Parses the `ENTRY` snapshot lines (ignoring the
/// trailing rule-line field, which only the review window needs).
fn list_pending(socket: &Path) -> Result<Vec<RecentBlock>> {
    let mut stream = UnixStream::connect(socket).context("connecting to list pending blocks")?;
    stream.write_all(b"list\n").context("sending list")?;
    stream.shutdown(Shutdown::Write).ok();
    let reader = BufReader::new(stream);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.context("reading list reply")?;
        if line == "END" {
            break;
        }
        let mut f = line.splitn(6, '\t');
        if f.next() != Some("ENTRY") {
            continue;
        }
        if let (Some(token), Some(kind), Some(target), Some(creator)) =
            (f.next(), f.next(), f.next(), f.next())
        {
            out.push(RecentBlock {
                token: token.to_string(),
                kind: kind.to_string(),
                target: target.to_string(),
                creator: creator.to_string(),
            });
        }
    }
    Ok(out)
}

/// Parse a `BLOCK\t<token>\t<kind>\t<target>\t<creator>` line; `None` for
/// anything else (e.g. the initial `OK subscribed`).
fn parse_block(line: &str) -> Option<RecentBlock> {
    let mut f = line.split('\t');
    if f.next()? != "BLOCK" {
        return None;
    }
    Some(RecentBlock {
        token: f.next()?.to_string(),
        kind: f.next()?.to_string(),
        target: f.next()?.to_string(),
        creator: f.next().unwrap_or("").to_string(),
    })
}

fn action_worker(rx: mpsc::Receiver<Action>, socket: PathBuf) {
    for action in rx {
        let verb = match action.kind {
            ActionKind::Once => "once",
            ActionKind::Always => "allow",
            ActionKind::Quarantine => "quarantine",
            ActionKind::Dismiss => "dismiss",
        };
        match send_command(&socket, verb, &action.token) {
            Ok(reply) => {
                info!("{verb} {} -> {reply}", action.token);
                notify_result(
                    action.kind,
                    &action.target,
                    reply.strip_prefix("OK ").is_some(),
                    &reply,
                );
            }
            Err(e) => {
                warn!("{verb} {} failed: {e:#}", action.token);
                notify_result(action.kind, &action.target, false, &format!("{e:#}"));
            }
        }
    }
}

/// One-shot control-socket request/reply (mirrors `linprov allow`).
fn send_command(socket: &Path, verb: &str, token: &str) -> Result<String> {
    let mut stream = UnixStream::connect(socket).context("connecting to control socket")?;
    stream.write_all(format!("{verb} {token}\n").as_bytes())?;
    stream.shutdown(Shutdown::Write).ok();
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(reply.trim().to_string())
}

fn notify_block(b: &RecentBlock) {
    let _ = notify_rust::Notification::new()
        .summary("linprov blocked an exec")
        .body(&format!(
            "{}\n{} · created by {}\nRight-click the linprov tray icon to allow.",
            b.target, b.kind, b.creator
        ))
        .icon("security-low")
        .show();
}

fn notify_result(kind: ActionKind, target: &str, ok: bool, detail: &str) {
    // A quarantine that failed because the file was swapped/redirected since
    // the block is a suspected race against the tool — surface it as a
    // critical, non-expiring alert rather than a notification that auto-fades.
    let tamper = !ok && matches!(kind, ActionKind::Quarantine) && detail.contains(TAMPER_MARKER);
    let summary = match (kind, ok) {
        (ActionKind::Quarantine, true) => "linprov: quarantined",
        (ActionKind::Quarantine, false) if tamper => {
            "⚠ linprov: POSSIBLE TAMPER — quarantine failed"
        }
        (ActionKind::Quarantine, false) => "linprov: quarantine failed",
        (ActionKind::Dismiss, _) => "linprov: dismissed",
        (_, true) => "linprov: allowed",
        (_, false) => "linprov: allow failed",
    };
    let mut n = notify_rust::Notification::new();
    n.summary(summary).body(&format!("{target}\n{detail}"));
    if tamper {
        n.urgency(notify_rust::Urgency::Critical)
            .timeout(notify_rust::Timeout::Never)
            .icon("dialog-warning");
    }
    let _ = n.show();
}

fn basename(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, b)| b).unwrap_or(path)
}

//! `linprov notify` — a user-session tray agent for interactive approvals.
//!
//! The daemon runs as root on the system bus and can't reach the user's
//! session bus where the tray/notifier live, so this agent bridges them.
//! It connects to the daemon's control socket (group `linprov`, exposed by
//! `notifications = "tray"`), `subscribe`s to block events, and presents a
//! StatusNotifierItem tray icon (via `ksni`) whose context menu lists
//! recent blocked execs — each with **Allow once / Allow always / Close**.
//! A buttonless desktop notification also fires per block as an alert.
//!
//! Menu clicks drive the same control-socket verbs `linprov allow` uses
//! (`allow` / `once <token>`). Run it from your sway config
//! (`exec linprov notify`); needs a StatusNotifierHost (e.g. waybar's tray).

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
}

impl ksni::Tray for LinprovTray {
    fn id(&self) -> String {
        "linprov".into()
    }
    fn title(&self) -> String {
        "linprov".into()
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
                let (t_once, t_always, t_close) =
                    (b.token.clone(), b.token.clone(), b.token.clone());
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
                                label: "Close".into(),
                                activate: Box::new(move |t: &mut Self| {
                                    t.recent.retain(|x| x.token != t_close)
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
    let handle = LinprovTray {
        recent: Vec::new(),
        tx,
    }
    .spawn()
    .map_err(|e| anyhow!("starting the tray failed ({e}); is a StatusNotifierHost running (e.g. waybar's tray module)?"))?;

    // Worker: applies menu clicks against the control socket.
    let worker_socket = args.socket.clone();
    std::thread::spawn(move || action_worker(rx, worker_socket));

    info!("linprov tray agent started; subscribing to {}", args.socket.display());
    // This thread owns the subscribe stream (reconnects forever).
    subscribe_loop(&args.socket, &handle);
    Ok(())
}

/// Connect, `subscribe`, and feed block events to the tray + notifications;
/// reconnect with a fixed backoff if the daemon goes away or restarts.
fn subscribe_loop(socket: &Path, handle: &ksni::blocking::Handle<LinprovTray>) {
    loop {
        if let Err(e) = subscribe_once(socket, handle) {
            warn!("control socket: {e:#}");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn subscribe_once(socket: &Path, handle: &ksni::blocking::Handle<LinprovTray>) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {} (is the daemon running with notifications=tray, and are you in the linprov group?)", socket.display()))?;
    stream.write_all(b"subscribe\n").context("sending subscribe")?;
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line.context("reading block stream")?;
        if let Some(b) = parse_block(&line) {
            notify_block(&b);
            let b2 = b.clone();
            handle.update(move |t: &mut LinprovTray| t.push(b2));
        }
    }
    Err(anyhow!("subscribe stream closed"))
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
        };
        match send_command(&socket, verb, &action.token) {
            Ok(reply) => {
                info!("{verb} {} -> {reply}", action.token);
                notify_result(&action.target, reply.strip_prefix("OK ").is_some(), &reply);
            }
            Err(e) => {
                warn!("{verb} {} failed: {e:#}", action.token);
                notify_result(&action.target, false, &format!("{e:#}"));
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
            "{}\n{} · created by {}\nOpen the linprov tray to allow.",
            b.target, b.kind, b.creator
        ))
        .icon("security-low")
        .show();
}

fn notify_result(target: &str, ok: bool, detail: &str) {
    let summary = if ok {
        "linprov: allowed"
    } else {
        "linprov: allow failed"
    };
    let _ = notify_rust::Notification::new()
        .summary(summary)
        .body(&format!("{target}\n{detail}"))
        .show();
}

fn basename(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, b)| b).unwrap_or(path)
}

//! `linprov review` — the desktop review window for pending blocked execs.
//!
//! Left-clicking the tray icon launches this (as its own process, so its egui
//! event loop doesn't fight ksni's). It `list`s the daemon's pending blocks,
//! shows them as a checkbox list, lets you expand each to pick *which*
//! components (dimensions) of the candidate rule to allowlist — pre-checked to
//! the captured exact-match default — and applies a bulk **Allow once / Allow
//! always / Quarantine / Dismiss** to everything selected in one go.
//!
//! Gated behind the `review-ui` cargo feature so headless/server installs (and
//! the published-crate default build) don't pull the egui/winit/glow stack.
//! Without the feature, [`run`] returns an explanatory error; the tray
//! right-click menu and `linprov allow`/`quarantine` still work.

use std::path::PathBuf;

use clap::Parser;

use crate::config::DEFAULT_CONTROL_SOCKET_PATH;

#[derive(Parser, Debug)]
pub struct ReviewArgs {
    /// Daemon control socket to connect to.
    #[arg(long, default_value = DEFAULT_CONTROL_SOCKET_PATH)]
    socket: PathBuf,
}

#[cfg(not(feature = "review-ui"))]
pub fn run(_args: ReviewArgs) -> anyhow::Result<()> {
    anyhow::bail!(
        "this linprov was built without the `review-ui` feature, so the review \
         window isn't available. Rebuild with `--features review-ui` (e.g. \
         `cargo install --force --features review-ui linprov`). Meanwhile the \
         tray right-click menu and `linprov allow`/`quarantine <token>` still work."
    )
}

#[cfg(feature = "review-ui")]
pub use imp::run;

#[cfg(feature = "review-ui")]
mod imp {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::Shutdown,
        os::unix::net::UnixStream,
        path::{Path, PathBuf},
        time::Duration,
    };

    use anyhow::{anyhow, Context, Result};
    use eframe::egui;

    use super::ReviewArgs;
    use crate::allowlist::{Dim, RuleSpec};

    /// A muted red for error / failure text and alerts.
    const ALERT: egui::Color32 = egui::Color32::from_rgb(0xd0, 0x60, 0x60);

    /// One selectable component (dimension) of a block's candidate rule.
    struct Comp {
        dim: Dim,
        value: String,
        checked: bool,
    }

    /// One pending block row in the window.
    struct Row {
        token: String,
        kind: String,
        target: String,
        creator: String,
        /// Row checkbox — which blocks a bulk action applies to.
        selected: bool,
        comps: Vec<Comp>,
        /// Last per-row action result (an error keeps the row; success hides it).
        status: Option<String>,
        /// Resolved this session (allowed/quarantined/dismissed) — hidden.
        done: bool,
    }

    #[derive(Clone, Copy)]
    enum Action {
        Once,
        Always,
        Quarantine,
        Dismiss,
    }

    struct ReviewApp {
        socket: PathBuf,
        rows: Vec<Row>,
        banner: Option<String>,
    }

    pub fn run(args: ReviewArgs) -> Result<()> {
        let rows = fetch_pending(&args.socket)
            .with_context(|| format!("listing pending blocks from {}", args.socket.display()))?;
        let app = ReviewApp {
            socket: args.socket,
            rows,
            banner: None,
        };
        let opts = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([760.0, 580.0])
                .with_min_inner_size([520.0, 320.0])
                .with_title("linprov — review blocked execs")
                // Stable Wayland app_id so a tiling WM can target it — e.g. in
                // sway: `for_window [app_id="linprov-review"] floating enable`.
                .with_app_id("linprov-review"),
            ..Default::default()
        };
        eframe::run_native("linprov-review", opts, Box::new(|_cc| Ok(Box::new(app))))
            .map_err(|e| anyhow!("starting the review window: {e}"))
    }

    impl eframe::App for ReviewApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            egui::TopBottomPanel::top("hdr").show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.heading("Blocked execs");
                    let pending = self.rows.iter().filter(|r| !r.done).count();
                    ui.label(format!("· {pending} pending"));
                    if ui.button("⟳ Refresh").clicked() {
                        match fetch_pending(&self.socket) {
                            Ok(rows) => {
                                self.rows = rows;
                                self.banner = None;
                            }
                            Err(e) => self.banner = Some(format!("refresh failed: {e:#}")),
                        }
                    }
                    if ui.button("Select all").clicked() {
                        for r in self.rows.iter_mut().filter(|r| !r.done) {
                            r.selected = true;
                        }
                    }
                    if ui.button("Select none").clicked() {
                        for r in &mut self.rows {
                            r.selected = false;
                        }
                    }
                });
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    let any = self.rows.iter().any(|r| r.selected && !r.done);
                    let mut act = None;
                    ui.add_enabled_ui(any, |ui| {
                        if ui.button("✔ Allow once").clicked() {
                            act = Some(Action::Once);
                        }
                        if ui.button("✔✔ Allow always").clicked() {
                            act = Some(Action::Always);
                        }
                        if ui.button("⚠ Quarantine").clicked() {
                            act = Some(Action::Quarantine);
                        }
                        if ui.button("✕ Dismiss").clicked() {
                            act = Some(Action::Dismiss);
                        }
                    });
                    if let Some(a) = act {
                        self.apply(a);
                    }
                    ui.separator();
                    if ui.button("Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                if let Some(b) = &self.banner {
                    ui.colored_label(ALERT, b);
                }
                ui.add_space(4.0);
            });

            egui::CentralPanel::default().show(ctx, |ui| {
                if self.rows.iter().all(|r| r.done) {
                    ui.add_space(24.0);
                    ui.vertical_centered(|ui| ui.label("No pending blocks. 🎉"));
                    return;
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for row in self.rows.iter_mut().filter(|r| !r.done) {
                            row_ui(ui, row);
                            ui.separator();
                        }
                    });
            });
        }
    }

    fn row_ui(ui: &mut egui::Ui, row: &mut Row) {
        ui.horizontal(|ui| {
            ui.checkbox(&mut row.selected, "");
            let title = format!(
                "[{}]  {}  ·  {}",
                row.kind,
                basename(&row.target),
                row.creator
            );
            egui::CollapsingHeader::new(title)
                .id_salt(&row.token)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(&row.target).monospace().weak());
                    ui.add_space(4.0);
                    ui.label("Allowlist these components (uncheck to make the rule broader):");
                    for c in &mut row.comps {
                        ui.checkbox(
                            &mut c.checked,
                            format!("{} = {}", c.dim.as_key(), c.value),
                        );
                    }
                });
        });
        if let Some(s) = &row.status {
            ui.colored_label(ALERT, s);
        }
    }

    impl ReviewApp {
        /// Apply `action` to every selected, not-yet-resolved row. Each row's
        /// result is recorded inline; a success hides the row, an error keeps
        /// it with the daemon's message.
        fn apply(&mut self, action: Action) {
            for row in self.rows.iter_mut().filter(|r| r.selected && !r.done) {
                let cmd = match action {
                    Action::Once | Action::Always => {
                        let dims: Vec<&str> = row
                            .comps
                            .iter()
                            .filter(|c| c.checked)
                            .map(|c| c.dim.as_key())
                            .collect();
                        if dims.is_empty() {
                            row.status =
                                Some("select at least one component to allowlist".into());
                            continue;
                        }
                        let verb = if matches!(action, Action::Once) {
                            "once"
                        } else {
                            "allow"
                        };
                        format!("{verb} {} dims={}", row.token, dims.join(","))
                    }
                    Action::Quarantine => format!("quarantine {}", row.token),
                    Action::Dismiss => format!("dismiss {}", row.token),
                };
                match send_command(&self.socket, &cmd) {
                    Ok(reply) if reply.starts_with("OK") => {
                        row.done = true;
                        row.selected = false;
                        row.status = None;
                    }
                    Ok(reply) => row.status = Some(reply.trim_start_matches("ERR ").to_string()),
                    Err(e) => row.status = Some(format!("{e:#}")),
                }
            }
        }
    }

    /// `list` the pending blocks from the daemon and parse them into rows.
    /// Each `ENTRY` line carries the canonical candidate rule, which we parse
    /// back into per-dimension components for the checkboxes (pre-checked).
    fn fetch_pending(socket: &Path) -> Result<Vec<Row>> {
        let mut stream = UnixStream::connect(socket)
            .with_context(|| format!("connecting to {}", socket.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.write_all(b"list\n").context("sending list")?;
        stream.shutdown(Shutdown::Write).ok();

        let reader = BufReader::new(stream);
        let mut rows = Vec::new();
        for line in reader.lines() {
            let line = line.context("reading list reply")?;
            if line == "END" {
                break;
            }
            let mut f = line.splitn(6, '\t');
            if f.next() != Some("ENTRY") {
                continue;
            }
            let (token, kind, target, creator, rule_line) =
                match (f.next(), f.next(), f.next(), f.next(), f.next()) {
                    (Some(t), Some(k), Some(tg), Some(c), Some(r)) => (t, k, tg, c, r),
                    _ => continue,
                };
            let comps = RuleSpec::parse(rule_line)
                .map(|spec| {
                    spec.components()
                        .into_iter()
                        .map(|(dim, value)| Comp {
                            dim,
                            value,
                            checked: true,
                        })
                        .collect()
                })
                .unwrap_or_default();
            rows.push(Row {
                token: token.to_string(),
                kind: kind.to_string(),
                target: target.to_string(),
                creator: creator.to_string(),
                selected: true,
                comps,
                status: None,
                done: false,
            });
        }
        Ok(rows)
    }

    /// One-shot control-socket request/reply (mirrors the tray's worker).
    fn send_command(socket: &Path, line: &str) -> Result<String> {
        let mut stream =
            UnixStream::connect(socket).context("connecting to the control socket")?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.write_all(format!("{line}\n").as_bytes())?;
        stream.shutdown(Shutdown::Write).ok();
        let mut reply = String::new();
        stream.read_to_string(&mut reply)?;
        Ok(reply.trim().to_string())
    }

    fn basename(path: &str) -> &str {
        path.rsplit_once('/').map(|(_, b)| b).unwrap_or(path)
    }
}

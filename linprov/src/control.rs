//! Daemon-side rule control behind the `linprov allow` / `quarantine`
//! control socket: the pending-blocks token table and the in-memory
//! transient (`--once`) rules. The BPF rules map is always (re)seeded from
//! `combined()` = persistent file rules ∪ transient rules, so an `allow
//! --once` survives SIGHUP file-reloads but is gone on daemon restart
//! (never written to disk), while a plain `allow` is appended to the
//! allowlist file.
//!
//! The pending-blocks table ([`BlocksTable`]) is the source of truth for
//! "what's awaiting a decision": a block adds an entry, and `allow` / `once`
//! / `quarantine` / `dismiss` remove it (a recurrence re-adds it). The
//! `list` control verb snapshots it for the review window, and every
//! resolution broadcasts a [`ControlEvent::Resolved`] so the live tray drops
//! the entry too — no matter which client actioned it.

use std::{
    collections::{HashMap, VecDeque},
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use linprov_common::{siphash, MAX_RULES};

use crate::{
    allowlist::{Dim, RuleSpec, Rules},
    config::restrict_perms,
    encoding::escape,
};

/// Cap on remembered block tokens (LRU). Plenty for "see it in the log,
/// allow it" without unbounded growth on a noisy enforce box.
const MAX_BLOCKS: usize = 512;

/// A blocked exec, broadcast to control-socket `subscribe`rs (the
/// `linprov notify` tray agent). Tab-serialized on the wire as
/// `BLOCK\t<token>\t<kind>\t<target>\t<creator>`.
#[derive(Clone, Debug)]
pub struct BlockEvent {
    /// `"exec"` (ELF/shebang, bprm) or `"script"` (interpreter-loaded).
    pub kind: &'static str,
    /// The `[allow: <token>]` handle — feeds `allow`/`once`/`quarantine`.
    pub token: String,
    /// The blocked path (exec target / script).
    pub target: String,
    /// Resolved creator exe path, or the creator `comm` if the path is
    /// unknown — for display in the tray/notification.
    pub creator: String,
}

impl BlockEvent {
    /// One-line wire form for the subscribe stream. Fields are
    /// tab-separated and assumed newline/tab-free (paths from `d_path`,
    /// a hex token, a short kind).
    pub fn to_wire(&self) -> String {
        // target/creator are kernel-derived paths; escape them so an embedded
        // tab or newline can't desync this tab-separated, newline-framed wire.
        format!(
            "BLOCK\t{}\t{}\t{}\t{}",
            self.token,
            self.kind,
            escape(&self.target),
            escape(&self.creator)
        )
    }
}

/// An event on the control broadcast channel that `subscribe`rs follow: a
/// new block, or a token that left the pending set (allowed, quarantined, or
/// dismissed — by *any* client) so every view can drop it and stay in sync.
#[derive(Clone, Debug)]
pub enum ControlEvent {
    Block(BlockEvent),
    /// A token that's no longer pending. Wire: `RESOLVED\t<token>`.
    Resolved(String),
}

impl ControlEvent {
    pub fn to_wire(&self) -> String {
        match self {
            ControlEvent::Block(b) => b.to_wire(),
            ControlEvent::Resolved(token) => format!("RESOLVED\t{token}"),
        }
    }
}

/// What a block token resolves to: the candidate allow rule (for
/// `allow`/`once`, optionally projected onto a chosen dim subset), the
/// display strings, and the live target path + its `dev`/`ino` captured at
/// block time (for `quarantine`, which moves the file and re-verifies the
/// identity to refuse one swapped since the block).
#[derive(Clone, Debug)]
pub struct BlockRecord {
    /// Stable token (keyed SipHash of `rule_line`).
    pub token: String,
    /// `"exec"` or `"script"`.
    pub kind: String,
    /// Canonical candidate allow rule line (all dims captured for this
    /// block); `allow`/`once` apply this (or a projection of it).
    pub rule_line: String,
    /// Blocked path, for display + as the file `quarantine` moves.
    pub target: String,
    /// Creator exe path (or `comm` fallback), for display.
    pub creator: String,
    /// `dev`/`ino` of `target` at block time; `quarantine` re-stats and
    /// refuses on a mismatch. `(0, 0)` if the file was already gone.
    pub dev: u64,
    pub ino: u64,
}

/// Bounded `token → BlockRecord` table of *pending* blocked execs. An entry
/// is dropped once it's actioned (`allow`/`once`/`quarantine`/`dismiss`); a
/// later recurrence of the same block re-adds it (refreshing the file
/// identity, which may have changed between occurrences).
pub struct BlocksTable {
    map: HashMap<String, BlockRecord>,
    order: VecDeque<String>,
    /// The per-install keyed-hash key (the `(k0, k1)` seeded into the BPF
    /// `KEY` map). Block tokens are SipHash of the rule line under this key,
    /// so they can't be guessed or forged by someone who doesn't hold it
    /// (the old token was an invertible 32-bit FNV of the rule line).
    k0: u64,
    k1: u64,
}

impl BlocksTable {
    fn new(k0: u64, k1: u64) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            k0,
            k1,
        }
    }

    /// Record a pending blocked exec (its candidate rule + display strings +
    /// file identity) and return its stable token (keyed SipHash of the rule
    /// line — identical blocks reuse it, so the token an operator copies from
    /// the log keeps resolving). A repeat refreshes the target/identity.
    pub fn record(
        &mut self,
        kind: &str,
        rule_line: String,
        target: String,
        creator: String,
        dev: u64,
        ino: u64,
    ) -> String {
        // Keyed (not the old invertible FNV) so a control-socket client can't
        // forge or guess a token for a block it didn't witness — but kept at
        // the historical 8-hex width (low 32 bits of the keyed hash) so the
        // `[allow: <token>]` log contract and anything parsing it are unchanged.
        let token = format!("{:08x}", siphash(self.k0, self.k1, rule_line.as_bytes()) as u32);
        if let Some(rec) = self.map.get_mut(&token) {
            // Same rule line recurred: refresh the volatile bits (the file may
            // have been replaced between blocks), keep its place in the order.
            rec.target = target;
            rec.creator = creator;
            rec.dev = dev;
            rec.ino = ino;
        } else {
            if self.order.len() >= MAX_BLOCKS {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
            self.order.push_back(token.clone());
            self.map.insert(
                token.clone(),
                BlockRecord {
                    token: token.clone(),
                    kind: kind.to_string(),
                    rule_line,
                    target,
                    creator,
                    dev,
                    ino,
                },
            );
        }
        token
    }

    fn rule_for(&self, token: &str) -> Option<&str> {
        self.map.get(token).map(|r| r.rule_line.as_str())
    }

    /// The full record for `token` (path + identity), for `quarantine`.
    pub fn record_for(&self, token: &str) -> Option<BlockRecord> {
        self.map.get(token).cloned()
    }

    /// Snapshot of the pending blocks, oldest-first, for the `list` verb.
    pub fn list(&self) -> Vec<BlockRecord> {
        self.order
            .iter()
            .filter_map(|t| self.map.get(t).cloned())
            .collect()
    }

    /// Drop a token once it's been actioned. Returns whether it was present.
    pub fn remove(&mut self, token: &str) -> bool {
        if self.map.remove(token).is_some() {
            self.order.retain(|t| t != token);
            true
        } else {
            false
        }
    }
}

/// Daemon-side rule control: the persistent allowlist path, the in-memory
/// transient (`allow --once`) rules, and the recent-blocks table.
pub struct Control {
    allowlist_path: Option<PathBuf>,
    transient: Vec<RuleSpec>,
    pub blocks: BlocksTable,
}

impl Control {
    pub fn new(allowlist_path: Option<PathBuf>, k0: u64, k1: u64) -> Self {
        Self {
            allowlist_path,
            transient: Vec::new(),
            blocks: BlocksTable::new(k0, k1),
        }
    }

    /// The full rule set to seed into the BPF map: file rules (freshly
    /// read, so a SIGHUP/allow picks up external edits) plus the in-memory
    /// transient rules.
    pub fn combined(&self) -> Result<Vec<RuleSpec>> {
        let mut rules = match &self.allowlist_path {
            Some(p) => Rules::load(p)?.rules,
            None => Vec::new(),
        };
        rules.extend(self.transient.iter().cloned());
        Ok(rules)
    }

    /// Apply the rule for `token`, optionally projected onto `dims` (the
    /// review window's per-component selection — e.g. keep only
    /// `creator_process` and drop the noisy `target_filename`). `None` →
    /// the full candidate rule (the default exact-match dims captured at
    /// block time).
    ///
    /// `once` → add to the in-memory transient set (active until daemon
    /// restart, never written to the file). Otherwise append it to the
    /// allowlist file (deduped against disk). Returns the applied rule line;
    /// the caller reseeds from `combined()` and drops the token from the
    /// pending table.
    pub fn apply_with_dims(
        &mut self,
        token: &str,
        once: bool,
        dims: Option<&[Dim]>,
    ) -> Result<String> {
        let candidate = self
            .blocks
            .rule_for(token)
            .ok_or_else(|| {
                anyhow!("unknown token `{token}` (expired, or nothing blocked this daemon session)")
            })?
            .to_string();
        // Parse the candidate (and normalize it through the parser).
        let spec = RuleSpec::parse(&candidate)
            .with_context(|| format!("re-parsing candidate rule `{candidate}`"))?;
        let line = match dims {
            Some(ds) => {
                let projected = spec.project(ds);
                if projected.flags == 0 {
                    return Err(anyhow!(
                        "none of the selected dimensions are recorded for this block"
                    ));
                }
                projected.to_line()
            }
            None => spec.to_line(),
        };
        // The projection may have dropped to a less-specific rule; re-validate.
        let parsed =
            RuleSpec::parse(&line).with_context(|| format!("re-parsing projected rule `{line}`"))?;

        if once {
            if self.transient.iter().any(|r| r.to_line() == line) {
                return Ok(line); // already active this session
            }
            // Transient rules seed into the BPF map AFTER the file rules
            // (see `combined`), so once file ∪ transient fills the map any
            // new transient rule is silently truncated at seed time. Refuse
            // loudly instead of replying OK for a rule that won't take effect.
            if self.combined()?.len() >= MAX_RULES {
                return Err(anyhow!(
                    "allowlist is at capacity ({MAX_RULES} rules); `allow --once` can't \
                     take effect — transient rules seed after the file rules and would \
                     be dropped. Trim the allowlist (or restart) first."
                ));
            }
            self.transient.push(parsed);
        } else {
            self.append_persistent(&line)?;
        }
        Ok(line)
    }

    fn append_persistent(&mut self, line: &str) -> Result<()> {
        let path = self.allowlist_path.as_ref().ok_or_else(|| {
            anyhow!("no allowlist file configured; cannot persist this rule (try --once)")
        })?;
        // Dedup against what's already on disk so repeated `allow` of the
        // same block doesn't pile up duplicate lines.
        if Rules::load(path)?.rules.iter().any(|r| r.to_line() == line) {
            return Ok(());
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening `{}` to append", path.display()))?;
        restrict_perms(path); // first `allow` may create it — keep it 0640
        writeln!(f, "{line}").with_context(|| format!("appending `{line}`"))?;
        f.sync_data().ok();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Record a minimal pending block for tests (no real file behind it).
    fn record(control: &mut Control, rule_line: &str) -> String {
        control
            .blocks
            .record("exec", rule_line.to_string(), "/t".to_string(), "c".to_string(), 0, 0)
    }

    #[test]
    fn once_refused_when_allowlist_at_capacity() {
        // A full allowlist file (MAX_RULES distinct rules) leaves no room for
        // a transient rule — it would be silently truncated at seed time — so
        // `allow --once` must error rather than reply OK (finding N5).
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 0..MAX_RULES {
            writeln!(f, "creator_uid={i}").unwrap();
        }
        f.flush().unwrap();
        let mut control = Control::new(Some(f.path().to_path_buf()), 1, 2);
        let token = record(&mut control, "creator_uid=4294967295");
        let err = control.apply_with_dims(&token, true, None).unwrap_err();
        assert!(format!("{err:#}").contains("at capacity"), "{err:#}");
    }

    #[test]
    fn once_added_when_under_capacity() {
        let mut control = Control::new(None, 1, 2); // no file → 0 rules
        let token = record(&mut control, "creator_uid=1000");
        let rule = control.apply_with_dims(&token, true, None).unwrap();
        assert_eq!(rule, "creator_uid=1000");
        assert_eq!(control.combined().unwrap().len(), 1);
    }

    #[test]
    fn apply_with_dims_projects_to_subset() {
        // The review window's per-component allow: keep only creator_process
        // from a rich candidate, dropping the noisy target/landing dims.
        let mut control = Control::new(None, 1, 2);
        let token = record(
            &mut control,
            "target_filename=/var/x;landing_filename=x.tmp;creator_process=/usr/lib/apt/methods/http;creator_comm=http",
        );
        let rule = control
            .apply_with_dims(&token, true, Some(&[Dim::CreatorProcess]))
            .unwrap();
        assert_eq!(rule, "creator_process=/usr/lib/apt/methods/http");
    }

    #[test]
    fn apply_with_dims_rejects_absent_dims() {
        // Selecting a dim the block never recorded yields an empty rule —
        // refuse rather than write a no-op (match-nothing) line.
        let mut control = Control::new(None, 1, 2);
        let token = record(&mut control, "creator_comm=curl");
        let err = control
            .apply_with_dims(&token, true, Some(&[Dim::TargetFolder]))
            .unwrap_err();
        assert!(format!("{err:#}").contains("none of the selected"), "{err:#}");
    }

    #[test]
    fn remove_drops_pending_entry() {
        let mut control = Control::new(None, 1, 2);
        let token = record(&mut control, "creator_uid=1000");
        assert_eq!(control.blocks.list().len(), 1);
        assert!(control.blocks.remove(&token));
        assert!(control.blocks.list().is_empty());
        assert!(!control.blocks.remove(&token)); // second remove is a no-op
    }
}

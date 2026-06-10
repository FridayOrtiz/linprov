//! Daemon-side rule control behind the `linprov allow` control socket:
//! the recent-blocks token table and the in-memory transient (`--once`)
//! rules. The BPF rules map is always (re)seeded from `combined()` =
//! persistent file rules ∪ transient rules, so an `allow --once` survives
//! SIGHUP file-reloads but is gone on daemon restart (never written to
//! disk), while a plain `allow` is appended to the allowlist file.

use std::{
    collections::{HashMap, VecDeque},
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use linprov_common::fnv_hash;

use crate::allowlist::{RuleSpec, Rules};

/// Cap on remembered block tokens (LRU). Plenty for "see it in the log,
/// allow it" without unbounded growth on a noisy enforce box.
const MAX_BLOCKS: usize = 512;

/// Bounded `token → candidate-rule-line` table of recent blocked execs.
#[derive(Default)]
pub struct BlocksTable {
    map: HashMap<String, String>,
    order: VecDeque<String>,
}

impl BlocksTable {
    /// Record the candidate rule for a blocked exec and return its stable
    /// token (short FNV of the rule line — identical blocks reuse it, so
    /// the token an operator copies from the log keeps resolving).
    pub fn record(&mut self, rule_line: String) -> String {
        let token = format!("{:08x}", fnv_hash(&rule_line) as u32);
        if !self.map.contains_key(&token) {
            if self.order.len() >= MAX_BLOCKS {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
            self.order.push_back(token.clone());
            self.map.insert(token.clone(), rule_line);
        }
        token
    }

    fn rule_for(&self, token: &str) -> Option<&str> {
        self.map.get(token).map(String::as_str)
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
    pub fn new(allowlist_path: Option<PathBuf>) -> Self {
        Self {
            allowlist_path,
            transient: Vec::new(),
            blocks: BlocksTable::default(),
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

    /// Apply the rule for `token`. `once` → add to the in-memory transient
    /// set (active until daemon restart, never written to the file).
    /// Otherwise append it to the allowlist file (deduped against disk).
    /// Returns the applied rule line; the caller reseeds from `combined()`.
    pub fn apply(&mut self, token: &str, once: bool) -> Result<String> {
        let line = self
            .blocks
            .rule_for(token)
            .ok_or_else(|| {
                anyhow!("unknown token `{token}` (expired, or nothing blocked this daemon session)")
            })?
            .to_string();
        // Validate it still parses (and normalize it through the parser).
        RuleSpec::parse(&line).with_context(|| format!("re-parsing candidate rule `{line}`"))?;

        if once {
            if !self.transient.iter().any(|r| r.to_line() == line) {
                let spec = RuleSpec::parse(&line)?;
                self.transient.push(spec);
            }
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
        writeln!(f, "{line}").with_context(|| format!("appending `{line}`"))?;
        f.sync_data().ok();
        Ok(())
    }
}

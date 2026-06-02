//! Allowlist: each line is one rule whose `<dim>=<value>;<dim>=<value>`
//! conditions AND together. Multiple lines OR.
//!
//! ```text
//! # uid 1000 downloading with curl is fine, anywhere
//! creator_uid=1000;creator_comm=curl
//!
//! # uid 1000 may execute firefox-dropped binaries from ~/.local/bin
//! execution_uid=1000;creator_comm=firefox;target_folder=/home/user/.local/bin
//! ```

use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::Mutex,
};

use anyhow::{anyhow, Context, Result};
use clap::ValueEnum;
use linprov_common::{dim, fnv_hash, AllowRule, COMM_LEN, MAX_RULES};
use serde::Deserialize;

/// Allowlist dimensions. Used for `--soak=<csv>`, for the
/// `<dim>=<value>` entries in the allowlist file, and for the
/// `soak = [...]` array in the TOML config file.
#[derive(Clone, Copy, Debug, Deserialize, ValueEnum, PartialEq, Eq, Hash)]
#[clap(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Dim {
    /// Exact full path of the executed binary (at execve time).
    TargetFilename,
    /// Any `/`-terminated ancestor of the executed binary's path.
    TargetFolder,
    /// Basename (final component) of the file where it was first written.
    LandingFilename,
    /// The landing file's immediate parent folder, or any ancestor of it
    /// (nested, up to `MAX_FOLDER_ANCESTORS` levels).
    LandingFolder,
    /// Full exe path of the writer (`/proc/$pid/exe`).
    CreatorProcess,
    /// 16-byte `comm` of the writer.
    CreatorComm,
    /// UID of the writer.
    CreatorUid,
    /// UID running the `execve`.
    ExecutionUid,
}

impl Dim {
    pub fn as_key(self) -> &'static str {
        match self {
            Dim::TargetFilename => "target_filename",
            Dim::TargetFolder => "target_folder",
            Dim::LandingFilename => "landing_filename",
            Dim::LandingFolder => "landing_folder",
            Dim::CreatorProcess => "creator_process",
            Dim::CreatorComm => "creator_comm",
            Dim::CreatorUid => "creator_uid",
            Dim::ExecutionUid => "execution_uid",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "target_filename" => Dim::TargetFilename,
            "target_folder" => Dim::TargetFolder,
            "landing_filename" => Dim::LandingFilename,
            "landing_folder" => Dim::LandingFolder,
            "creator_process" => Dim::CreatorProcess,
            "creator_comm" => Dim::CreatorComm,
            "creator_uid" => Dim::CreatorUid,
            "execution_uid" => Dim::ExecutionUid,
            _ => return None,
        })
    }
}

/// Parsed rule, ready to be packed into [`AllowRule`] for the BPF map.
/// Field naming mirrors the dim names.
#[derive(Debug, Default, Clone)]
pub struct RuleSpec {
    pub flags: u32,
    pub target_filename: Option<String>,
    pub target_folder: Option<String>,
    pub landing_filename: Option<String>,
    pub landing_folder: Option<String>,
    pub creator_process: Option<String>,
    pub creator_comm: Option<String>,
    pub creator_uid: Option<u32>,
    pub execution_uid: Option<u32>,
}

impl RuleSpec {
    /// Parse one allowlist line. Expects `dim=val[;dim=val]*` after
    /// stripping comments / whitespace. Empty rules (zero dims) are an
    /// error at the caller; this just parses.
    pub fn parse(line: &str) -> Result<Self> {
        let mut spec = Self::default();
        for cond in line.split(';') {
            let cond = cond.trim();
            if cond.is_empty() {
                continue;
            }
            let (k, v) = cond
                .split_once('=')
                .ok_or_else(|| anyhow!("condition `{cond}` is missing `=`"))?;
            let k = k.trim();
            let v = v.trim();
            let dim = Dim::parse(k).ok_or_else(|| anyhow!("unknown dimension `{k}`"))?;
            spec.set(dim, v)
                .with_context(|| format!("condition `{k}={v}`"))?;
        }
        if spec.flags == 0 {
            return Err(anyhow!("rule has no conditions"));
        }
        Ok(spec)
    }

    pub fn set(&mut self, d: Dim, value: &str) -> Result<()> {
        let bit = match d {
            Dim::TargetFilename => dim::TARGET_FILENAME,
            Dim::TargetFolder => dim::TARGET_FOLDER,
            Dim::LandingFilename => dim::LANDING_FILENAME,
            Dim::LandingFolder => dim::LANDING_FOLDER,
            Dim::CreatorProcess => dim::CREATOR_PROCESS,
            Dim::CreatorComm => dim::CREATOR_COMM,
            Dim::CreatorUid => dim::CREATOR_UID,
            Dim::ExecutionUid => dim::EXECUTION_UID,
        };
        if self.flags & bit != 0 {
            return Err(anyhow!(
                "dim `{}` specified twice in the same rule",
                d.as_key()
            ));
        }
        self.flags |= bit;

        // Path-shaped dims are stored as FNV hashes (see `pack`), so
        // there's no length ceiling on rule values — a 4096-byte path
        // hashes to the same 8 bytes as a short one.
        match d {
            Dim::TargetFilename => {
                self.target_filename = Some(value.to_string());
            }
            Dim::TargetFolder => {
                let (folder, recursive) = split_recursive(value);
                self.target_folder = Some(normalize_folder(folder));
                if recursive {
                    self.flags |= dim::TARGET_FOLDER_RECURSIVE;
                }
            }
            Dim::LandingFilename => {
                self.landing_filename = Some(value.to_string());
            }
            Dim::LandingFolder => {
                let (folder, recursive) = split_recursive(value);
                self.landing_folder = Some(normalize_folder(folder));
                if recursive {
                    self.flags |= dim::LANDING_FOLDER_RECURSIVE;
                }
            }
            Dim::CreatorProcess => {
                self.creator_process = Some(value.to_string());
            }
            Dim::CreatorComm => {
                if value.len() >= COMM_LEN {
                    return Err(anyhow!(
                        "creator_comm `{value}` is too long ({} bytes; max {})",
                        value.len(),
                        COMM_LEN - 1
                    ));
                }
                self.creator_comm = Some(value.to_string());
            }
            Dim::CreatorUid => {
                let uid: u32 = value
                    .parse()
                    .with_context(|| format!("creator_uid `{value}` is not a u32"))?;
                self.creator_uid = Some(uid);
            }
            Dim::ExecutionUid => {
                let uid: u32 = value
                    .parse()
                    .with_context(|| format!("execution_uid `{value}` is not a u32"))?;
                self.execution_uid = Some(uid);
            }
        }
        Ok(())
    }

    /// Render the rule back to its canonical line form (dims in the
    /// enum's declared order, joined by `;`). Used for dedup / soak.
    pub fn to_line(&self) -> String {
        let mut parts = Vec::new();
        for d in DIM_ORDER {
            let bit = dim_bit(*d);
            if self.flags & bit == 0 {
                continue;
            }
            let v = match d {
                Dim::TargetFilename => self.target_filename.clone(),
                // Re-emit the trailing `*` for recursive folder rules so
                // the canonical line round-trips (and dedups correctly).
                Dim::TargetFolder => self.target_folder.clone().map(|f| {
                    if self.flags & dim::TARGET_FOLDER_RECURSIVE != 0 {
                        format!("{f}*")
                    } else {
                        f
                    }
                }),
                Dim::LandingFilename => self.landing_filename.clone(),
                Dim::LandingFolder => self.landing_folder.clone().map(|f| {
                    if self.flags & dim::LANDING_FOLDER_RECURSIVE != 0 {
                        format!("{f}*")
                    } else {
                        f
                    }
                }),
                Dim::CreatorProcess => self.creator_process.clone(),
                Dim::CreatorComm => self.creator_comm.clone(),
                Dim::CreatorUid => self.creator_uid.map(|u| u.to_string()),
                Dim::ExecutionUid => self.execution_uid.map(|u| u.to_string()),
            };
            if let Some(v) = v {
                parts.push(format!("{}={v}", d.as_key()));
            }
        }
        parts.join(";")
    }

    /// Pack into the on-the-wire [`AllowRule`] shape. Strings are
    /// hashed; userspace and BPF agree on FNV-1a-64.
    pub fn pack(&self) -> AllowRule {
        let mut creator_comm = [0u8; COMM_LEN];
        if let Some(c) = &self.creator_comm {
            let b = c.as_bytes();
            let n = b.len().min(COMM_LEN - 1);
            creator_comm[..n].copy_from_slice(&b[..n]);
        }
        AllowRule {
            flags: self.flags,
            creator_uid: self.creator_uid.unwrap_or(0),
            execution_uid: self.execution_uid.unwrap_or(0),
            _pad: 0,
            creator_comm,
            target_filename_hash: self.target_filename.as_deref().map(fnv_hash).unwrap_or(0),
            target_folder_hash: self.target_folder.as_deref().map(fnv_hash).unwrap_or(0),
            landing_filename_hash: self.landing_filename.as_deref().map(fnv_hash).unwrap_or(0),
            landing_folder_hash: self.landing_folder.as_deref().map(fnv_hash).unwrap_or(0),
            creator_process_hash: self.creator_process.as_deref().map(fnv_hash).unwrap_or(0),
        }
    }
}

const DIM_ORDER: &[Dim] = &[
    Dim::TargetFilename,
    Dim::TargetFolder,
    Dim::LandingFilename,
    Dim::LandingFolder,
    Dim::CreatorProcess,
    Dim::CreatorComm,
    Dim::CreatorUid,
    Dim::ExecutionUid,
];

fn dim_bit(d: Dim) -> u32 {
    match d {
        Dim::TargetFilename => dim::TARGET_FILENAME,
        Dim::TargetFolder => dim::TARGET_FOLDER,
        Dim::LandingFilename => dim::LANDING_FILENAME,
        Dim::LandingFolder => dim::LANDING_FOLDER,
        Dim::CreatorProcess => dim::CREATOR_PROCESS,
        Dim::CreatorComm => dim::CREATOR_COMM,
        Dim::CreatorUid => dim::CREATOR_UID,
        Dim::ExecutionUid => dim::EXECUTION_UID,
    }
}

fn normalize_folder(value: &str) -> String {
    if value.ends_with('/') {
        value.to_string()
    } else {
        // Folder rules must end in `/` so the BPF FNV walk hits the
        // hash exactly when crossing the corresponding separator.
        format!("{value}/")
    }
}

/// Split a folder rule value into `(folder, recursive)`. A trailing `*`
/// means recursive (match the folder or any descendant); without it the
/// rule is exact (only files directly in the folder). `/opt/app/*` and
/// `/opt/app*` both yield `("/opt/app", true)` → normalized
/// `/opt/app/`; `/opt/app/` yields `("/opt/app/", false)`.
fn split_recursive(value: &str) -> (&str, bool) {
    match value.strip_suffix('*') {
        Some(rest) => (rest, true),
        None => (value, false),
    }
}

/// Full parsed allowlist: an ordered list of rules. Dedup happens at
/// load time (canonical [`RuleSpec::to_line`] form).
#[derive(Debug, Default)]
pub struct Rules {
    pub rules: Vec<RuleSpec>,
    seen_lines: HashSet<String>,
}

impl Rules {
    pub fn load(path: &Path) -> Result<Self> {
        let mut rules = Self::default();
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(rules),
            Err(e) => return Err(anyhow!("opening allowlist `{}`: {e}", path.display())),
        };
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line.with_context(|| format!("reading line {}", i + 1))?;
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let spec = RuleSpec::parse(trimmed)
                .with_context(|| format!("parsing allowlist line {}: `{trimmed}`", i + 1))?;
            rules.insert(spec);
        }
        Ok(rules)
    }

    pub fn insert(&mut self, spec: RuleSpec) -> bool {
        let line = spec.to_line();
        if !self.seen_lines.insert(line) {
            return false;
        }
        self.rules.push(spec);
        true
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn check_capacity(&self) -> Result<()> {
        if self.rules.len() > MAX_RULES {
            return Err(anyhow!(
                "{} rules exceeds BPF map capacity ({MAX_RULES}). \
                 Trim the allowlist or bump MAX_RULES.",
                self.rules.len()
            ));
        }
        Ok(())
    }
}

/// Soak-mode state: which dims to record, the append handle, and the
/// dedup set shared with [`Rules::seen_lines`] at startup.
pub struct Soak {
    pub dims: Vec<Dim>,
    pub seen: Mutex<HashSet<String>>,
    pub writer: Mutex<File>,
}

impl Soak {
    pub fn open(path: &Path, dims: Vec<Dim>, preload: &Rules) -> Result<Self> {
        let writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening allowlist `{}` for soak append", path.display()))?;
        Ok(Self {
            dims,
            seen: Mutex::new(preload.seen_lines.clone()),
            writer: Mutex::new(writer),
        })
    }

    /// Build a rule from the soak dims using the values in `ctx`, then
    /// append it to the file if not previously seen. Returns the rule
    /// line iff actually written.
    pub fn record(&self, ctx: &OriginContext<'_>) -> Result<Option<String>> {
        let mut spec = RuleSpec::default();
        for d in &self.dims {
            let val: Option<String> = match d {
                // Target dims come from the live exec path — always
                // present, any length.
                Dim::TargetFilename => non_empty(ctx.target_filename),
                Dim::TargetFolder => folder_of(ctx.target_filename),
                // Landing + creator dims are resolved from the audit db
                // (the record only carries hashes). `None` means the db
                // couldn't resolve the hash — skip that dim rather than
                // emit a rule that can't be matched.
                Dim::LandingFilename => ctx.landing_basename.map(str::to_string),
                Dim::LandingFolder => ctx.landing_folder.map(str::to_string),
                Dim::CreatorProcess => ctx.creator_path.map(str::to_string),
                Dim::CreatorComm => non_empty(ctx.creator_comm),
                Dim::CreatorUid => Some(ctx.creator_uid.to_string()),
                Dim::ExecutionUid => Some(ctx.execution_uid.to_string()),
            };
            let Some(val) = val else { continue };
            if let Err(e) = spec.set(*d, &val) {
                log::warn!("soak: skipping invalid {} value `{val}`: {e}", d.as_key());
            }
        }
        if spec.flags == 0 {
            return Ok(None);
        }

        let line = spec.to_line();
        {
            let mut seen = self.seen.lock().expect("soak seen mutex poisoned");
            if !seen.insert(line.clone()) {
                return Ok(None);
            }
        }
        let mut w = self.writer.lock().expect("soak writer mutex poisoned");
        writeln!(w, "{line}").with_context(|| format!("appending `{line}`"))?;
        w.sync_data().ok();
        Ok(Some(line))
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Immediate parent directory of `path`, with a trailing `/` so it
/// hashes identically to the BPF target-folder walk and to
/// `normalize_folder`.
fn folder_of(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    match path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => Some(format!("{parent}/")),
        Some((_, _)) => Some("/".to_string()),
        None => None,
    }
}

/// Values the soak emitter needs per execve event.
///
/// `target_filename` is the live exec path (always present). The
/// landing/creator fields are resolved from the audit db — `None` when
/// the db can't map the record's hash back to a path, in which case
/// soak skips that dimension rather than emit an unmatchable rule.
pub struct OriginContext<'a> {
    pub target_filename: &'a str,
    pub landing_folder: Option<&'a str>,
    pub landing_basename: Option<&'a str>,
    pub creator_path: Option<&'a str>,
    pub creator_comm: &'a str,
    pub creator_uid: u32,
    pub execution_uid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_dim() {
        let r = RuleSpec::parse("creator_comm=curl").unwrap();
        assert_eq!(r.flags, dim::CREATOR_COMM);
        assert_eq!(r.creator_comm.as_deref(), Some("curl"));
    }

    #[test]
    fn parse_multi_dim_anded() {
        let r = RuleSpec::parse("creator_uid=1000;creator_comm=curl").unwrap();
        assert_eq!(r.flags, dim::CREATOR_UID | dim::CREATOR_COMM);
        assert_eq!(r.creator_uid, Some(1000));
        assert_eq!(r.creator_comm.as_deref(), Some("curl"));
    }

    #[test]
    fn parse_trailing_semicolons_and_whitespace_ok() {
        let r = RuleSpec::parse("  creator_uid = 1000 ;; creator_comm = curl ; ").unwrap();
        assert_eq!(r.flags, dim::CREATOR_UID | dim::CREATOR_COMM);
    }

    #[test]
    fn parse_rejects_unknown_dim() {
        let err = RuleSpec::parse("nope=1").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unknown dimension"), "{msg}");
    }

    #[test]
    fn parse_rejects_empty_rule() {
        let err = RuleSpec::parse(";;").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no conditions"), "{msg}");
    }

    #[test]
    fn parse_rejects_missing_equals() {
        let err = RuleSpec::parse("creator_comm").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing `=`"), "{msg}");
    }

    #[test]
    fn parse_rejects_duplicate_dim() {
        let err = RuleSpec::parse("creator_uid=1;creator_uid=2").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("specified twice"), "{msg}");
    }

    #[test]
    fn parse_rejects_bad_uid() {
        let err = RuleSpec::parse("creator_uid=notanumber").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a u32"), "{msg}");
    }

    #[test]
    fn target_folder_normalizes_trailing_slash() {
        let r = RuleSpec::parse("target_folder=/opt/installed").unwrap();
        assert_eq!(r.target_folder.as_deref(), Some("/opt/installed/"));

        let r = RuleSpec::parse("target_folder=/opt/installed/").unwrap();
        assert_eq!(r.target_folder.as_deref(), Some("/opt/installed/"));
    }

    #[test]
    fn round_trip_canonical_line() {
        // Conditions are emitted in DIM_ORDER, which doesn't necessarily
        // match input order — round-tripping through to_line() yields
        // the canonical form.
        let r = RuleSpec::parse("creator_comm=curl;target_filename=/x").unwrap();
        let line = r.to_line();
        assert_eq!(line, "target_filename=/x;creator_comm=curl");

        // The canonical form re-parses identically.
        let r2 = RuleSpec::parse(&line).unwrap();
        assert_eq!(r2.to_line(), line);
    }

    #[test]
    fn folder_of_immediate_parent() {
        assert_eq!(
            folder_of("/opt/my-app/bin/foo").as_deref(),
            Some("/opt/my-app/bin/")
        );
        assert_eq!(folder_of("/foo").as_deref(), Some("/"));
        // Any length — no truncation, since the rule value is hashed.
        let deep = format!("/{}/x", "a".repeat(5000));
        assert_eq!(
            folder_of(&deep).as_deref(),
            Some(&*format!("/{}/", "a".repeat(5000)))
        );
    }

    #[test]
    fn long_path_rule_parses_without_length_limit() {
        // Path-shaped dims hash to 8 bytes regardless of length.
        let long = format!("/opt/{}/bin/", "seg/".repeat(2000));
        let r = RuleSpec::parse(&format!("target_folder={long}")).unwrap();
        assert_eq!(r.flags, dim::TARGET_FOLDER);
    }

    #[test]
    fn folder_recursive_suffix_parses_and_round_trips() {
        // Trailing `*` → recursive modifier; folder normalized without it.
        let r = RuleSpec::parse("target_folder=/opt/app/*").unwrap();
        assert_eq!(r.flags, dim::TARGET_FOLDER | dim::TARGET_FOLDER_RECURSIVE);
        assert_eq!(r.target_folder.as_deref(), Some("/opt/app/"));
        assert_eq!(r.to_line(), "target_folder=/opt/app/*");

        // No `*` → exact, no modifier bit.
        let r = RuleSpec::parse("target_folder=/opt/app/").unwrap();
        assert_eq!(r.flags, dim::TARGET_FOLDER);
        assert_eq!(r.to_line(), "target_folder=/opt/app/");

        // Same for landing_folder, and `*` without a trailing slash still
        // normalizes the folder.
        let r = RuleSpec::parse("landing_folder=/home/u/Downloads*").unwrap();
        assert_eq!(r.flags, dim::LANDING_FOLDER | dim::LANDING_FOLDER_RECURSIVE);
        assert_eq!(r.landing_folder.as_deref(), Some("/home/u/Downloads/"));
        assert_eq!(r.to_line(), "landing_folder=/home/u/Downloads/*");
    }

    #[test]
    fn pack_sets_only_required_hashes() {
        let r = RuleSpec::parse("creator_uid=1000").unwrap();
        let packed = r.pack();
        assert_eq!(packed.flags, dim::CREATOR_UID);
        assert_eq!(packed.creator_uid, 1000);
        // Cleared dims still have a default-valued field — the BPF side
        // ignores them because the flag bit is off.
        assert_eq!(packed.target_filename_hash, 0);
        assert_eq!(packed.creator_process_hash, 0);
    }

    #[test]
    fn pack_creator_process_hashes_match_fnv() {
        let r = RuleSpec::parse("creator_process=/usr/bin/curl").unwrap();
        let packed = r.pack();
        assert_eq!(packed.flags, dim::CREATOR_PROCESS);
        assert_eq!(packed.creator_process_hash, fnv_hash("/usr/bin/curl"));
    }

    #[test]
    fn rules_dedup_on_canonical_line() {
        let mut rules = Rules::default();
        assert!(rules.insert(RuleSpec::parse("creator_uid=1000").unwrap()));
        assert!(!rules.insert(RuleSpec::parse("creator_uid=1000").unwrap()));
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn rules_load_skips_comments_and_blanks() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "# top comment").unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp, "creator_comm=curl  # inline comment").unwrap();
        writeln!(tmp, "creator_uid=1000;creator_comm=curl").unwrap();
        tmp.flush().unwrap();
        let rules = Rules::load(tmp.path()).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn capacity_check_fires_above_max_rules() {
        let mut rules = Rules::default();
        for i in 0..(MAX_RULES + 1) {
            // Use unique creator_uid values so dedup doesn't collapse them.
            let spec = RuleSpec::parse(&format!("creator_uid={i}")).unwrap();
            rules.insert(spec);
        }
        assert!(rules.check_capacity().is_err());
    }
}

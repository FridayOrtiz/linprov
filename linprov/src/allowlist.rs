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
use linprov_common::{
    dim, fnv_hash, AllowRule, COMM_LEN, MAX_RULES, PATH_HASH_SCAN_LEN,
};

/// Allowlist dimensions. Used both for `--soak=<csv>` and for the
/// `<dim>=<value>` entries in the allowlist file.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Hash)]
#[clap(rename_all = "snake_case")]
pub enum Dim {
    /// Exact full path of the executed binary (at execve time).
    TargetFilename,
    /// Any `/`-terminated ancestor of the executed binary's path.
    TargetFolder,
    /// Exact full path of the file where it was first written.
    LandingFilename,
    /// Any ancestor of the file's landing path.
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

        match d {
            Dim::TargetFilename => {
                check_path_len(d, value)?;
                self.target_filename = Some(value.to_string());
            }
            Dim::TargetFolder => {
                let v = normalize_folder(value);
                check_path_len(d, &v)?;
                self.target_folder = Some(v);
            }
            Dim::LandingFilename => {
                check_path_len(d, value)?;
                self.landing_filename = Some(value.to_string());
            }
            Dim::LandingFolder => {
                let v = normalize_folder(value);
                check_path_len(d, &v)?;
                self.landing_folder = Some(v);
            }
            Dim::CreatorProcess => {
                check_path_len(d, value)?;
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
                Dim::TargetFolder => self.target_folder.clone(),
                Dim::LandingFilename => self.landing_filename.clone(),
                Dim::LandingFolder => self.landing_folder.clone(),
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

fn check_path_len(d: Dim, value: &str) -> Result<()> {
    if value.len() > PATH_HASH_SCAN_LEN {
        return Err(anyhow!(
            "{} value `{value}` is too long ({} bytes; BPF only hashes the first {})",
            d.as_key(),
            value.len(),
            PATH_HASH_SCAN_LEN
        ));
    }
    Ok(())
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
                Dim::TargetFilename => non_empty(ctx.target_filename),
                Dim::TargetFolder => folder_of(ctx.target_filename),
                Dim::LandingFilename => non_empty(ctx.landing_filename),
                Dim::LandingFolder => folder_of(ctx.landing_filename),
                Dim::CreatorProcess => non_empty(ctx.creator_path),
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

/// All values the soak emitter / BPF rule check care about per event.
pub struct OriginContext<'a> {
    pub target_filename: &'a str,
    pub landing_filename: &'a str,
    pub creator_path: &'a str,
    pub creator_comm: &'a str,
    pub creator_uid: u32,
    pub execution_uid: u32,
}

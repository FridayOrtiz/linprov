//! Multi-dimensional allowlist: parsing, per-dimension rule sets, and
//! soak-mode rule emission.
//!
//! File format. One rule per line; `#` introduces a comment:
//! ```text
//! target_filename=/tmp/probe-a
//! target_folder=/opt/installed/   # trailing slash matters
//! creator_process=/usr/bin/curl
//! creator_comm=curl
//! creator_uid=1000
//! execution_uid=0
//!
//! /legacy/bare/path               # interpreted as target_filename
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
use linprov_common::{COMM_LEN, CREATOR_PATH_LEN, FOLDER_HASH_SCAN_LEN, PATH_LEN};

/// Allowlist dimensions. The names here drive both `--soak=<csv>` parsing
/// and the file format (`<dim>=<value>`).
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Hash)]
#[clap(rename_all = "snake_case")]
pub enum Dim {
    /// Exact target path of the executed binary.
    TargetFilename,
    /// Longest-prefix match against the executed path. Rule values should
    /// end in `/`.
    TargetFolder,
    /// Exact full path of the creator process (resolved by userspace via
    /// `/proc/$pid/exe`).
    CreatorProcess,
    /// Exact match against the 16-char creator `comm`.
    CreatorComm,
    /// UID of the writer in `file_open`.
    CreatorUid,
    /// UID of the process performing the `execve`.
    ExecutionUid,
}

impl Dim {
    pub fn as_key(self) -> &'static str {
        match self {
            Dim::TargetFilename => "target_filename",
            Dim::TargetFolder => "target_folder",
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
            "creator_process" => Dim::CreatorProcess,
            "creator_comm" => Dim::CreatorComm,
            "creator_uid" => Dim::CreatorUid,
            "execution_uid" => Dim::ExecutionUid,
            _ => return None,
        })
    }
}

/// Parsed allowlist, bucketed per dimension. Strings already have any
/// trailing whitespace trimmed; the BPF map seeding step pads them out.
#[derive(Debug, Default)]
pub struct Rules {
    pub target_filenames: HashSet<String>,
    pub target_folders: HashSet<String>,
    pub creator_processes: HashSet<String>,
    pub creator_comms: HashSet<String>,
    pub creator_uids: HashSet<u32>,
    pub execution_uids: HashSet<u32>,
}

impl Rules {
    /// Load rules from `path`. Missing file is not an error — we return
    /// an empty rule set so soak runs can start from scratch.
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
            rules.insert_rule(trimmed).with_context(|| {
                format!("parsing allowlist line {}: `{}`", i + 1, trimmed)
            })?;
        }
        Ok(rules)
    }

    /// Parse a single `<dim>=<value>` rule (or legacy bare path) and
    /// insert it. Public for tests / soak's incremental append path.
    pub fn insert_rule(&mut self, rule: &str) -> Result<()> {
        if let Some((k, v)) = rule.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            let dim = Dim::parse(k).ok_or_else(|| anyhow!("unknown dimension `{k}`"))?;
            self.insert_typed(dim, v)
        } else if rule.starts_with('/') {
            // legacy bare path — treat as target_filename
            self.target_filenames.insert(rule.to_string());
            Ok(())
        } else {
            Err(anyhow!(
                "expected `<dim>=<value>` or a leading-`/` legacy path"
            ))
        }
    }

    pub fn insert_typed(&mut self, dim: Dim, value: &str) -> Result<()> {
        match dim {
            Dim::TargetFilename => {
                self.target_filenames.insert(value.to_string());
            }
            Dim::TargetFolder => {
                let v = if value.ends_with('/') {
                    value.to_string()
                } else {
                    // Rule keys include the trailing `/` so the prefix
                    // can't slip across path components. Normalize here
                    // so the file format is forgiving.
                    format!("{value}/")
                };
                if v.len() > FOLDER_HASH_SCAN_LEN {
                    return Err(anyhow!(
                        "target_folder `{v}` is too long ({} bytes; max {})",
                        v.len(),
                        FOLDER_HASH_SCAN_LEN
                    ));
                }
                self.target_folders.insert(v);
            }
            Dim::CreatorProcess => {
                self.creator_processes.insert(value.to_string());
            }
            Dim::CreatorComm => {
                if value.len() >= COMM_LEN {
                    return Err(anyhow!(
                        "creator_comm `{value}` is too long ({} bytes; max {})",
                        value.len(),
                        COMM_LEN - 1
                    ));
                }
                self.creator_comms.insert(value.to_string());
            }
            Dim::CreatorUid => {
                let uid: u32 = value
                    .parse()
                    .with_context(|| format!("creator_uid `{value}` is not a u32"))?;
                self.creator_uids.insert(uid);
            }
            Dim::ExecutionUid => {
                let uid: u32 = value
                    .parse()
                    .with_context(|| format!("execution_uid `{value}` is not a u32"))?;
                self.execution_uids.insert(uid);
            }
        }
        Ok(())
    }

    pub fn total_len(&self) -> usize {
        self.target_filenames.len()
            + self.target_folders.len()
            + self.creator_processes.len()
            + self.creator_comms.len()
            + self.creator_uids.len()
            + self.execution_uids.len()
    }
}

/// Encode a path the way the eBPF program leaves it in the filename buffer
/// after `bpf_d_path`. The kernel helper:
///   1. Calls `d_path` which writes "<path>\0" right-aligned into the buffer.
///   2. memmoves the resulting string (path + NUL, length `n+1`) to the
///      front of the buffer, leaving the original right-aligned copy intact.
/// So the buffer ends up with the path at byte 0..=n (NUL terminator at n)
/// *and* a second copy of path-plus-NUL right-aligned at the tail.
///
/// Used for exact-match dimensions (target_filename, creator_process) where
/// the BPF lookup key is the full PATH_LEN buffer.
pub fn path_key(p: &str) -> [u8; PATH_LEN] {
    let mut key = [0u8; PATH_LEN];
    let bytes = p.as_bytes();
    let n = bytes.len().min(PATH_LEN - 1);
    if n == 0 {
        return key;
    }
    key[..n].copy_from_slice(&bytes[..n]);
    let tail_path_start = PATH_LEN - 1 - n;
    key[tail_path_start..tail_path_start + n].copy_from_slice(&bytes[..n]);
    key
}

/// Fixed-size encoding for creator_path lookups. The BPF side reads
/// `OriginRecord.creator_path` directly — userspace wrote it left-aligned
/// (no tail mirroring), so we encode the same way here.
pub fn creator_path_key(p: &str) -> [u8; CREATOR_PATH_LEN] {
    let mut key = [0u8; CREATOR_PATH_LEN];
    let bytes = p.as_bytes();
    let n = bytes.len().min(CREATOR_PATH_LEN - 1);
    key[..n].copy_from_slice(&bytes[..n]);
    key
}

pub fn comm_key(c: &str) -> [u8; COMM_LEN] {
    let mut key = [0u8; COMM_LEN];
    let bytes = c.as_bytes();
    let n = bytes.len().min(COMM_LEN - 1);
    key[..n].copy_from_slice(&bytes[..n]);
    key
}

/// Soak mode state: which dimensions to record, an append handle for the
/// file, and an in-memory dedup set keyed on the full literal rule line.
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
        let mut seen = HashSet::new();
        for v in &preload.target_filenames {
            seen.insert(format!("target_filename={v}"));
        }
        for v in &preload.target_folders {
            seen.insert(format!("target_folder={v}"));
        }
        for v in &preload.creator_processes {
            seen.insert(format!("creator_process={v}"));
        }
        for v in &preload.creator_comms {
            seen.insert(format!("creator_comm={v}"));
        }
        for v in &preload.creator_uids {
            seen.insert(format!("creator_uid={v}"));
        }
        for v in &preload.execution_uids {
            seen.insert(format!("execution_uid={v}"));
        }
        Ok(Self {
            dims,
            seen: Mutex::new(seen),
            writer: Mutex::new(writer),
        })
    }

    /// Emit allowlist rules for a marked exec. Each configured dimension
    /// produces zero or one new line (skipped if the value is empty or
    /// duplicate of a previously-seen rule).
    pub fn record(&self, target_path: &str, origin: &OriginContext<'_>) -> Result<Vec<String>> {
        let mut written = Vec::new();
        for dim in &self.dims {
            let value = match dim {
                Dim::TargetFilename => Some(target_path.to_string()),
                Dim::TargetFolder => match target_path.rsplit_once('/') {
                    Some((parent, _)) if !parent.is_empty() => Some(format!("{parent}/")),
                    Some((_, _)) => Some("/".to_string()),
                    None => None,
                },
                Dim::CreatorProcess => {
                    if origin.creator_path.is_empty() {
                        None
                    } else {
                        Some(origin.creator_path.to_string())
                    }
                }
                Dim::CreatorComm => {
                    if origin.creator_comm.is_empty() {
                        None
                    } else {
                        Some(origin.creator_comm.to_string())
                    }
                }
                Dim::CreatorUid => Some(origin.creator_uid.to_string()),
                Dim::ExecutionUid => Some(origin.execution_uid.to_string()),
            };
            let Some(value) = value else { continue };

            let line = format!("{}={}", dim.as_key(), value);
            {
                let mut seen = self.seen.lock().expect("soak seen mutex poisoned");
                if !seen.insert(line.clone()) {
                    continue;
                }
            }
            let mut w = self.writer.lock().expect("soak writer mutex poisoned");
            writeln!(w, "{line}").with_context(|| format!("appending `{line}`"))?;
            w.sync_data().ok();
            written.push(line);
        }
        Ok(written)
    }
}

/// Inputs to the per-event soak decision, materialized once by the handler.
pub struct OriginContext<'a> {
    pub creator_path: &'a str,
    pub creator_comm: &'a str,
    pub creator_uid: u32,
    pub execution_uid: u32,
}

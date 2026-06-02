//! Plaintext hash → path audit database.
//!
//! The v4 `OriginRecord` stores variable-length provenance fields
//! (creator exe, landing folder, landing basename) as FNV-1a-64 hashes
//! rather than path strings — that's what lets a landing folder of any
//! length fit in a fixed 64-byte record / xattr. The trade-off is that
//! a hash isn't human-readable on its own.
//!
//! This db closes that gap. Every time the daemon marks a file it
//! records the `hash → path` pairs it computed into a plaintext,
//! tab-separated file:
//!
//! ```text
//! a1b2c3d4e5f60718\t/home/user/Downloads/
//! 0f1e2d3c4b5a6978\tinstaller.sh
//! 1122334455667788\t/usr/bin/curl
//! ```
//!
//! The file is append-only with in-memory dedup, lives at a stable
//! path (`/var/lib/linprov/hashes.tsv` by default), and survives
//! reboots — so blocked-execve logs and `soak` rule emission can both
//! turn a record's hashes back into paths even for marks made in a
//! previous boot. It's deliberately greppable: `grep Downloads
//! hashes.tsv` shows every folder hash you've stored under Downloads,
//! and `grep <hash> hashes.tsv` resolves a hash seen in a log line.
//!
//! Enforcement never reads this db — the BPF program matches on hashes
//! alone. Losing or pruning the db only costs human readability, never
//! correctness.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::Mutex,
};

use anyhow::{Context, Result};
use linprov_common::fnv_hash;
use log::{debug, warn};

/// Open (loading existing entries) and append-tracking handle.
pub struct HashDb {
    map: Mutex<HashMap<u64, String>>,
    writer: Mutex<File>,
}

impl HashDb {
    /// Load any existing entries from `path`, then open it for append.
    /// Creates parent dirs and the file if missing.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating `{}`", parent.display()))?;
            }
        }

        let mut map = HashMap::new();
        match File::open(path) {
            Ok(f) => {
                for (i, line) in BufReader::new(f).lines().enumerate() {
                    let line = match line {
                        Ok(l) => l,
                        Err(e) => {
                            warn!("hashdb: read error on line {}: {e}", i + 1);
                            break;
                        }
                    };
                    let Some((hex, path_str)) = line.split_once('\t') else {
                        continue; // skip malformed / comment lines
                    };
                    if let Ok(hash) = u64::from_str_radix(hex.trim(), 16) {
                        map.insert(hash, path_str.to_string());
                    }
                }
                debug!(
                    "hashdb: loaded {} entries from {}",
                    map.len(),
                    path.display()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("opening `{}`", path.display())),
        }

        let writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening `{}` for append", path.display()))?;

        Ok(Self {
            map: Mutex::new(map),
            writer: Mutex::new(writer),
        })
    }

    /// Record `s` under its FNV hash. Idempotent: only the first sighting
    /// of a given hash is appended to the file. Returns the hash so
    /// callers can store it in the record without re-hashing.
    pub fn record(&self, s: &str) -> u64 {
        let hash = fnv_hash(s);
        let mut map = self.map.lock().expect("hashdb map mutex poisoned");
        if map.contains_key(&hash) {
            return hash;
        }
        map.insert(hash, s.to_string());
        // Drop the map lock before touching the file? Keep it: holding
        // both briefly preserves file-vs-map consistency and contention
        // is negligible (one append per newly-seen path).
        let mut w = self.writer.lock().expect("hashdb writer mutex poisoned");
        if let Err(e) = writeln!(w, "{hash:016x}\t{s}") {
            warn!("hashdb: failed to append {hash:016x} -> {s}: {e}");
        }
        hash
    }

    /// Resolve a hash back to the path it was recorded under, if known.
    pub fn resolve(&self, hash: u64) -> Option<String> {
        if hash == 0 {
            return None;
        }
        self.map
            .lock()
            .expect("hashdb map mutex poisoned")
            .get(&hash)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn record_resolve_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hashes.tsv");
        let db = HashDb::open(&path).unwrap();
        let h = db.record("/home/user/Downloads/");
        assert_eq!(db.resolve(h).as_deref(), Some("/home/user/Downloads/"));
        assert_eq!(db.resolve(0), None);
        assert_eq!(db.resolve(0xdead_beef), None);
    }

    #[test]
    fn dedup_and_persist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hashes.tsv");
        {
            let db = HashDb::open(&path).unwrap();
            db.record("/a/b/");
            db.record("/a/b/"); // dup, no second line
            db.record("foo.sh");
        }
        // Exactly two distinct lines on disk.
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2, "body was:\n{body}");
        // Reopen and confirm entries survive.
        let db = HashDb::open(&path).unwrap();
        assert_eq!(db.resolve(fnv_hash("/a/b/")).as_deref(), Some("/a/b/"));
        assert_eq!(db.resolve(fnv_hash("foo.sh")).as_deref(), Some("foo.sh"));
    }
}

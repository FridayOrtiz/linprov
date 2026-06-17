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
//! tab-separated file with three columns — `hash`, base64 (the
//! authoritative, exactly-reversible form linprov decodes), and a
//! best-effort human-readable rendering:
//!
//! ```text
//! a1b2c3d4e5f60718\tL2hvbWUvdXNlci9Eb3dubG9hZHMv\t/home/user/Downloads/
//! 0f1e2d3c4b5a6978\taW5zdGFsbGVyLnNo\tinstaller.sh
//! 1122334455667788\tL3Vzci9iaW4vY3VybA==\t/usr/bin/curl
//! ```
//!
//! The base64 column means a filename with an embedded newline/tab can't
//! inject a forged row, while the human column keeps the file greppable.
//! The file is append-only with in-memory dedup, lives at a stable path
//! (`/var/lib/linprov/hashes.tsv` by default), and survives reboots — so
//! blocked-execve logs and `soak` rule emission can both turn a record's
//! hashes back into paths even for marks made in a previous boot. It stays
//! deliberately greppable: `grep Downloads hashes.tsv` shows every folder
//! hash you've stored under Downloads, and `grep <hash> hashes.tsv`
//! resolves a hash seen in a log line. (Older two-column rows — `hash` plus
//! the raw path — are still read.)
//!
//! Enforcement never reads this db — the BPF program matches on hashes
//! alone. Losing or pruning the db only costs human readability, never
//! correctness.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Mutex,
};

use anyhow::{Context, Result};
use linprov_common::siphash;
use log::{debug, warn};

use crate::encoding::{b64, escape, unb64};

/// Open (loading existing entries) and append-tracking handle.
pub struct HashDb {
    map: Mutex<HashMap<u64, String>>,
    writer: Mutex<File>,
    /// The SipHash key (same one seeded into the BPF `KEY` map), so the audit
    /// db's hashes match the record/allowlist hashes (finding #3).
    k0: u64,
    k1: u64,
}

impl HashDb {
    /// Load any existing entries from `path`, then open it for append.
    /// Creates parent dirs and the file if missing. `(k0, k1)` is the keyed
    /// hash key; entries persisted in a previous run were hashed under the
    /// same (stable) key, so they stay valid.
    pub fn open(path: &Path, k0: u64, k1: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating `{}`", parent.display()))?;
                // Keep the state dir non-world-traversable so the audit db
                // (every marked path on the box) isn't reachable by other
                // local users. Best-effort; tightens an older 0755 dir too.
                let _ =
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
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
                        // Authoritative form is base64 (col 2). The optional
                        // human column (col 3) is display-only; we ignore it.
                        // Legacy 2-column rows stored the raw path directly.
                        let raw = match path_str.split_once('\t') {
                            Some((b64_col, _human)) => match unb64(b64_col) {
                                Some(p) => p,
                                None => continue, // corrupt base64 — skip
                            },
                            None => path_str.to_string(), // legacy <hash>\t<raw>
                        };
                        // In-memory map holds the raw path: resolve() feeds soak
                        // rule emission, which re-hashes it and must match the
                        // BPF-side hash of the raw bytes.
                        map.insert(hash, raw);
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
            // Born 0640 (owner rw, group r) rather than the umask default, so
            // there's no world-readable window before `restrict_perms` runs.
            // Only affects creation; an existing file keeps its perms.
            .mode(0o640)
            .open(path)
            .with_context(|| format!("opening `{}` for append", path.display()))?;

        Ok(Self {
            map: Mutex::new(map),
            writer: Mutex::new(writer),
            k0,
            k1,
        })
    }

    /// Record `s` under its FNV hash. Idempotent: only the first sighting
    /// of a given hash is appended to the file. Returns the hash so
    /// callers can store it in the record without re-hashing.
    pub fn record(&self, s: &str) -> u64 {
        let hash = siphash(self.k0, self.k1, s.as_bytes());
        let mut map = self.map.lock().expect("hashdb map mutex poisoned");
        if map.contains_key(&hash) {
            return hash;
        }
        map.insert(hash, s.to_string()); // map holds raw; hash is over raw
        // Drop the map lock before touching the file? Keep it: holding
        // both briefly preserves file-vs-map consistency and contention
        // is negligible (one append per newly-seen path).
        //
        // Three tab-separated columns: hash, base64 (authoritative — exactly
        // reversible, so a filename's embedded newline/tab can't inject a
        // forged row), and a best-effort human column for `grep`/eyeballing.
        let mut w = self.writer.lock().expect("hashdb writer mutex poisoned");
        if let Err(e) = writeln!(w, "{hash:016x}\t{}\t{}", b64(s), escape(s)) {
            warn!("hashdb: failed to append {hash:016x}: {e}");
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

    const K0: u64 = 0x1111_2222_3333_4444;
    const K1: u64 = 0x5555_6666_7777_8888;

    #[test]
    fn record_resolve_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hashes.tsv");
        let db = HashDb::open(&path, K0, K1).unwrap();
        let h = db.record("/home/user/Downloads/");
        assert_eq!(h, siphash(K0, K1, b"/home/user/Downloads/"));
        assert_eq!(db.resolve(h).as_deref(), Some("/home/user/Downloads/"));
        assert_eq!(db.resolve(0), None);
        assert_eq!(db.resolve(0xdead_beef), None);
    }

    #[test]
    fn dedup_and_persist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hashes.tsv");
        {
            let db = HashDb::open(&path, K0, K1).unwrap();
            db.record("/a/b/");
            db.record("/a/b/"); // dup, no second line
            db.record("foo.sh");
        }
        // Exactly two distinct lines on disk.
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2, "body was:\n{body}");
        // Reopen (same key) and confirm entries survive.
        let db = HashDb::open(&path, K0, K1).unwrap();
        assert_eq!(db.resolve(siphash(K0, K1, b"/a/b/")).as_deref(), Some("/a/b/"));
        assert_eq!(db.resolve(siphash(K0, K1, b"foo.sh")).as_deref(), Some("foo.sh"));
    }

    #[test]
    fn injection_path_stored_base64_resolves_raw() {
        // A filename carrying a newline + tab would otherwise forge a second
        // row in this TSV (finding #4). The authoritative base64 column has
        // no structural bytes, so it stays one row and decodes back exactly.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hashes.tsv");
        let evil = "/tmp/a\tb\nDEADBEEFDEADBEEF\t/etc/shadow";
        let h = {
            let db = HashDb::open(&path, K0, K1).unwrap();
            db.record(evil)
        };
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 1, "expected one row, got:\n{body}");
        // hash \t base64 \t human — exactly three columns.
        let cols: Vec<&str> = body.trim_end().split('\t').collect();
        assert_eq!(cols.len(), 3, "want 3 columns, got {cols:?}");
        assert_eq!(h, siphash(K0, K1, evil.as_bytes()));
        // Reopen → decode base64 → exact raw path.
        let db = HashDb::open(&path, K0, K1).unwrap();
        assert_eq!(db.resolve(h).as_deref(), Some(evil));
    }

    #[test]
    fn legacy_two_column_rows_still_load() {
        // A hashes.tsv written by an older linprov: <hash>\t<raw path>. The
        // stored hash is opaque to us — resolve() just maps it back.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hashes.tsv");
        let raw = "/home/u/Downloads/x";
        let legacy_hash: u64 = 0x0123_4567_89ab_cdef;
        let mut f = File::create(&path).unwrap();
        writeln!(f, "{legacy_hash:016x}\t{raw}").unwrap();
        drop(f);
        let db = HashDb::open(&path, K0, K1).unwrap();
        assert_eq!(db.resolve(legacy_hash).as_deref(), Some(raw));
    }
}

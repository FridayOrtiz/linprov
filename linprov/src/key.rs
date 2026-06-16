//! Per-install secret key for the keyed path hash (SipHash, finding #3).
//!
//! FNV is invertible, so a local attacker can construct a path that hashes to
//! an allowlisted path's value. SipHash keyed with a secret the attacker
//! doesn't know fixes that — but only if the key stays secret and *stable*:
//! every mark (the `security.bpf.linprov.origin` xattr) stores SipHash values
//! computed under this key, so a changed key silently invalidates every
//! existing mark (they re-mark on next open). Hence generate-once, persist
//! root-only, never rotate without accepting a full re-mark.

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use log::info;

/// The 128-bit SipHash key, split into the two words SipHash takes.
#[derive(Clone, Copy)]
pub struct HashKey {
    pub k0: u64,
    pub k1: u64,
}

impl HashKey {
    /// Load the key from `path`, or generate + persist a fresh random one
    /// (mode 0600) if the file doesn't exist yet.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) if bytes.len() >= 16 => Ok(Self::from_bytes(&bytes)),
            Ok(_) => Err(anyhow!(
                "key file `{}` is too short (corrupt?). Remove it to regenerate — \
                 note this invalidates every existing mark (they re-mark on next open).",
                path.display()
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                key.persist(path)?;
                info!(
                    "generated a fresh path-hash key at {} (0600)",
                    path.display()
                );
                Ok(key)
            }
            Err(e) => Err(e).with_context(|| format!("reading key `{}`", path.display())),
        }
    }

    fn generate() -> Result<Self> {
        // /dev/urandom is the simplest CSPRNG source without a new dependency.
        let mut f = fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
        let mut buf = [0u8; 16];
        f.read_exact(&mut buf)
            .context("reading 16 random key bytes from /dev/urandom")?;
        Ok(Self::from_bytes(&buf))
    }

    fn from_bytes(b: &[u8]) -> Self {
        // b.len() >= 16 guaranteed by callers.
        let k0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(b[8..16].try_into().unwrap());
        Self { k0, k1 }
    }

    fn persist(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating `{}`", parent.display()))?;
            }
        }
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&self.k0.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.k1.to_le_bytes());
        // Create 0600 from the outset (no world-readable window).
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating key file `{}`", path.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("writing key `{}`", path.display()))?;
        f.sync_data().ok();
        // Belt-and-suspenders if an odd umask interfered.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn generate_persist_reload_is_stable_and_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let k1 = HashKey::load_or_create(&path).unwrap();
        // Second load returns the SAME key (stable across "reboots").
        let k2 = HashKey::load_or_create(&path).unwrap();
        assert_eq!((k1.k0, k1.k1), (k2.k0, k2.k1));
        // A real key is (almost surely) not all-zero.
        assert!(k1.k0 != 0 || k1.k1 != 0);
        // Stored root-only.
        let mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode {mode:o}");
    }
}

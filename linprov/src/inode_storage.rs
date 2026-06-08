//! Userspace handle to the in-kernel `INODE_MARKS`
//! (`BPF_MAP_TYPE_INODE_STORAGE`) map.
//!
//! The eBPF `file_open` hook writes the `OriginRecord` into `INODE_MARKS`
//! with `creator_path_hash == 0` — it can't cheaply resolve the creator's
//! exe path in-kernel. Userspace later resolves that hash (from
//! `/proc/$pid/exe`) and writes it into the xattr, but historically *not*
//! back into the in-kernel record.
//!
//! That gap matters for two paths:
//!   * **direct exec** — `bprm_check_security` falls back to the (more
//!     expensive) xattr kfunc whenever the inode-storage record has a zero
//!     `creator_path_hash`;
//!   * **taint propagation** — a process that reads a marked file inherits
//!     the source's record *from `INODE_MARKS`* (same-boot), so a zero
//!     creator hash would propagate to every derived file.
//!
//! So after augmenting a record, userspace back-fills it here. Inode storage
//! is keyed from userspace by an **open file descriptor** whose inode the
//! kernel resolves, which is exactly what aya's typed [`InodeStorage`] map
//! exposes.

use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use aya::{
    maps::{InodeStorage, Map, MapData},
    Pod,
};
use linprov_common::OriginRecord;

/// Newtype so we can `impl aya::Pod` for the map value without tripping the
/// orphan rule (`OriginRecord` lives in `linprov-common`, which can't see
/// aya). `repr(transparent)` keeps the layout identical to `OriginRecord`,
/// so the kernel value size still matches.
#[repr(transparent)]
#[derive(Copy, Clone)]
struct OriginRecordWire(OriginRecord);

unsafe impl Pod for OriginRecordWire {}

/// Owns the userspace view of `INODE_MARKS` and back-fills augmented records.
pub struct InodeMarks {
    map: InodeStorage<MapData, OriginRecordWire>,
}

impl InodeMarks {
    /// Wrap the `INODE_MARKS` map (taken out of the loaded `Ebpf`). The map
    /// stays live in the kernel; the BPF programs keep their own load-time
    /// reference, so taking ownership here doesn't detach them.
    pub fn new(map: Map) -> Result<Self> {
        let map = InodeStorage::try_from(map).context("opening INODE_MARKS as inode storage")?;
        Ok(Self { map })
    }

    /// Back-fill the in-kernel record for the inode behind `file` with the
    /// augmented `rec` (creator fields now resolved). `BPF_ANY` (flags `0`)
    /// creates-or-updates. Best-effort: callers log and continue on error.
    pub fn backfill(&mut self, file: &impl AsRawFd, rec: &OriginRecord) -> Result<()> {
        self.map
            .insert(file, OriginRecordWire(*rec), 0)
            .context("INODE_MARKS insert")?;
        Ok(())
    }
}

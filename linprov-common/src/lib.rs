//! Types shared between the eBPF program (`linprov-ebpf`) and the userspace
//! daemon (`linprov`). Everything here must be `repr(C)` and Pod-friendly so
//! it survives a round-trip through a ring buffer and a kernel xattr.

#![cfg_attr(not(feature = "user"), no_std)]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const CREATOR_PATH_LEN: usize = 256;

/// Max path length the BPF folder walk inspects. Rules longer than this
/// can't possibly match — userspace rejects them at parse time.
pub const FOLDER_HASH_SCAN_LEN: usize = 96;

// FNV-1a-64 constants. Used by both sides to hash folder rules.
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
pub const FNV_PRIME: u64 = 0x100_0000_01b3;

/// Hash a rule string with FNV-1a-64 the same way the BPF folder walk
/// does: byte by byte, no trailing NUL, no padding.
pub fn folder_hash(s: &str) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

pub const XATTR_NAME: &str = "security.bpf.linprov.origin";

pub const EVENT_KIND_NETWORK_FILE_OPEN: u32 = 1;
pub const EVENT_KIND_EXECVE: u32 = 2;

/// Runtime mode communicated to the eBPF program via the CONFIG map.
pub const MODE_OBSERVE: u32 = 0;
pub const MODE_SOAK: u32 = 1; // eBPF behaves like OBSERVE; userspace records paths
pub const MODE_ENFORCE: u32 = 2;

/// Current schema version of [`OriginRecord`]. Records carrying a different
/// version are treated as unmarked — older xattrs from prior linprov
/// builds will need to be re-soaked.
pub const ORIGIN_VERSION: u32 = 2;

/// Provenance record. Carried in the `security.bpf.linprov.origin` xattr
/// and in the INODE_MARKS storage map.
///
/// `comm` and `creator_uid` are populated by BPF in `file_open`.
/// `creator_path` is populated by userspace after handling the ringbuf
/// event (reads `/proc/$pid/exe`). It may be all-zeros if the creator
/// process exited before userspace got to it — allowlist rules keyed on
/// `creator_process` won't match such records.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OriginRecord {
    pub version: u32,
    pub pid: u32,
    pub ts_boot_ns: u64,
    pub comm: [u8; COMM_LEN],
    pub creator_uid: u32,
    pub _pad: u32,
    pub creator_path: [u8; CREATOR_PATH_LEN],
}

/// Ring-buffer record. Two kinds:
///   NetworkFileOpen — informational; eBPF just wrote (or tried to write)
///     the xattr. `status` is the kfunc return code.
///   Execve — bprm_check fired AND the file already carried the mark.
///     `origin` is the record we read back; `status` is unused.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct Event {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub status: i32,
    pub comm: [u8; COMM_LEN],
    pub origin: OriginRecord,
    pub filename: [u8; PATH_LEN],
}

impl Event {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

//! Types shared between the eBPF program (`linprov-ebpf`) and the userspace
//! daemon (`linprov`). Everything here must be `repr(C)` and Pod-friendly so
//! it survives a round-trip through a ring buffer and a kernel xattr.

#![cfg_attr(not(feature = "user"), no_std)]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const CREATOR_PATH_LEN: usize = 256;

/// Max path length the BPF FNV walks inspect (one for `target_filename`,
/// one for `landing_filename`). Rules whose path-shaped values exceed
/// this can't possibly match — userspace rejects them at parse time.
pub const PATH_HASH_SCAN_LEN: usize = 64;

/// Max number of `/`-separated ancestor hashes we collect per filename
/// for folder-rule matching. Each represents one ancestor directory
/// (`/`, `/opt/`, `/opt/installed/`, …). Bounded so the verifier can
/// reason about the rule-iteration loop and the inner folder match.
pub const MAX_FOLDER_HASHES: usize = 4;

// FNV-1a-64 constants. Used by both sides to hash strings.
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
pub const FNV_PRIME: u64 = 0x100_0000_01b3;

/// Hash a string with FNV-1a-64. Byte-by-byte, no trailing NUL, no
/// padding — identical on the BPF and userspace sides.
pub fn fnv_hash(s: &str) -> u64 {
    fnv_hash_bytes(s.as_bytes())
}

pub fn fnv_hash_bytes(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

// ----- Allowlist rule. One per line in the allowlist file; each rule
// is a conjunction of (dim, value) conditions. Rules OR together.

/// `flags` bits on [`AllowRule`]. Set bits indicate which dims this
/// rule requires the record / execve context to match.
pub mod dim {
    pub const TARGET_FILENAME: u32 = 1 << 0;
    pub const TARGET_FOLDER: u32 = 1 << 1;
    pub const LANDING_FILENAME: u32 = 1 << 2;
    pub const LANDING_FOLDER: u32 = 1 << 3;
    pub const CREATOR_PROCESS: u32 = 1 << 4;
    pub const CREATOR_COMM: u32 = 1 << 5;
    pub const CREATOR_UID: u32 = 1 << 6;
    pub const EXECUTION_UID: u32 = 1 << 7;
}

/// Maximum number of allowlist rules carried by the BPF Array map.
/// Each rule check is ~30 ops + 2 folder lookups; the verifier walks
/// the full bounded loop, so this caps the per-execve cost.
pub const MAX_RULES: usize = 32;

/// One allowlist rule. Set bits in `flags` mark required dims; the
/// corresponding fields below are then compared against the record /
/// execve context at enforce time. Cleared bits → field ignored.
///
/// Strings are stored as FNV-1a-64 hashes (computed identically in
/// userspace and BPF). Collision probability for distinct strings under
/// FNV-64 is negligible at any realistic allowlist size.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct AllowRule {
    pub flags: u32,
    pub creator_uid: u32,
    pub execution_uid: u32,
    pub _pad: u32,
    pub creator_comm: [u8; COMM_LEN],
    pub target_filename_hash: u64,
    pub target_folder_hash: u64,
    pub landing_filename_hash: u64,
    pub landing_folder_hash: u64,
    pub creator_process_hash: u64,
}

pub const XATTR_NAME: &str = "security.bpf.linprov.origin";

pub const EVENT_KIND_NETWORK_FILE_OPEN: u32 = 1;
pub const EVENT_KIND_EXECVE: u32 = 2;

/// Runtime mode communicated to the eBPF program via the CONFIG map.
pub const MODE_OBSERVE: u32 = 0;
pub const MODE_SOAK: u32 = 1; // eBPF behaves like OBSERVE; userspace records paths
pub const MODE_ENFORCE: u32 = 2;

/// Current schema version of [`OriginRecord`]. Records carrying a different
/// version are treated as unmarked.
pub const ORIGIN_VERSION: u32 = 3;

/// Provenance record. Carried in the `security.bpf.linprov.origin` xattr
/// and in the INODE_MARKS storage map.
///
/// Filled in stages:
///   * BPF `file_open` writes `version`, `pid`, `ts_boot_ns`, `comm`,
///     `creator_uid`, and `landing_filename` (the path where the file
///     was first written, via `bpf_d_path`).
///   * Userspace, on the corresponding ringbuf event, reads
///     `/proc/$pid/exe` and overwrites the xattr with the augmented
///     record (`creator_path` filled).
///
/// `creator_path` may be all-zeros if the creator process exited
/// before userspace got to it. Allowlist rules keyed on
/// `creator_process` won't match such records, but other dims still do.
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
    pub landing_filename: [u8; PATH_LEN],
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

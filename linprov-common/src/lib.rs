//! Types shared between the eBPF program (`linprov-ebpf`) and the userspace
//! daemon (`linprov`). Everything here must be `repr(C)` and Pod-friendly so
//! it survives a round-trip through a ring buffer and a kernel xattr.

#![cfg_attr(not(feature = "user"), no_std)]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

pub const XATTR_NAME: &str = "security.bpf.linprov.origin";

pub const EVENT_KIND_NETWORK_FILE_OPEN: u32 = 1;
pub const EVENT_KIND_EXECVE: u32 = 2;

/// Runtime mode communicated to the eBPF program via the CONFIG map.
pub const MODE_OBSERVE: u32 = 0;
pub const MODE_SOAK: u32 = 1; // eBPF behaves like OBSERVE; userspace records paths
pub const MODE_ENFORCE: u32 = 2;

/// In-xattr provenance record. Written by the eBPF `file_open` hook via
/// `bpf_set_dentry_xattr`; read back by `bprm_check_security` via
/// `bpf_get_file_xattr`. Binary, fixed-size; userspace formats it for logs.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct OriginRecord {
    pub version: u32,
    pub pid: u32,
    pub ts_boot_ns: u64,
    pub comm: [u8; COMM_LEN],
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

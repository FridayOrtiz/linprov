//! Types shared between the eBPF program (`linprov-ebpf`) and the userspace
//! daemon (`linprov`). Everything here must be `repr(C)` and Pod-friendly so
//! it survives a round-trip through a ring buffer.

#![cfg_attr(not(feature = "user"), no_std)]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const IP_LEN: usize = 16;

pub const XATTR_NAME: &str = "security.linprov.origin";

pub const EVENT_KIND_NETWORK_FILE_OPEN: u32 = 1;
pub const EVENT_KIND_EXECVE: u32 = 2;

/// Single, fixed-size event placed in the ring buffer. We pay the cost of a
/// uniform layout (~308 B) to keep the eBPF side simple: one `reserve::<Event>`
/// path, one parse path in userspace. Variable-length records are an option
/// later if the noise from short events becomes meaningful.
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct Event {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub fd: i32,
    pub comm: [u8; COMM_LEN],
    pub remote_ip: [u8; IP_LEN],
    pub remote_port: u16,
    pub family: u16,
    pub _pad: u32,
    pub filename: [u8; PATH_LEN],
}

impl Event {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

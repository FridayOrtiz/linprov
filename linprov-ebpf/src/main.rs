//! linprov eBPF programs (BPF LSM edition).
//!
//! Model: a PID becomes "network-flagged" the first time it creates an AF_INET
//! or AF_INET6 socket. Any subsequent file_open with FMODE_WRITE for that PID
//! gets the file's path resolved via bpf_d_path() and emitted to userspace,
//! which applies the provenance xattr. A separate bprm_check_security hook
//! reports every exec; userspace inspects the target's xattr and logs marks.
//!
//! On the verifier: LSM hook args are BTF-typed (`trusted_ptr_linux_binprm`,
//! `trusted_ptr_struct_file`). Direct field loads on those pointers stay
//! trusted-typed in the verifier — but `bpf_probe_read_kernel` does NOT.
//! That's why we mirror enough of struct file / struct linux_binprm layout
//! here to let the BPF backend emit normal field loads; the verifier then
//! cross-references the kernel's BTF for the offset and re-types the result.
//!
//! Struct layouts are pinned to kernel 6.18 / x86_64. Field offsets confirmed
//! via `bpftool btf dump file /sys/kernel/btf/vmlinux format raw`.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::path as bpf_path,
    cty::{c_char, c_void},
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{lsm, map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use linprov_common::{Event, EVENT_KIND_EXECVE, EVENT_KIND_NETWORK_FILE_OPEN, PATH_LEN};

// Aya 0.13's helpers don't expose bpf_d_path. Declare it locally; helper id
// 147 is stable. Sig: long bpf_d_path(struct path *, char *buf, u32 sz).
#[inline(always)]
unsafe fn bpf_d_path(p: *mut bpf_path, buf: *mut c_char, sz: u32) -> i64 {
    let fun: unsafe extern "C" fn(*mut bpf_path, *mut c_char, u32) -> i64 =
        core::mem::transmute(147usize);
    fun(p, buf, sz)
}

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

const FMODE_WRITE: u32 = 0x2;

/// Just enough of `struct path` for size/alignment. We never read the fields
/// ourselves; we only ever pass a `*mut KernelPath` (re-cast to aya's opaque
/// `path`) to bpf_d_path so the kernel walks it.
#[repr(C)]
struct KernelPath {
    _mnt: *const c_void,
    _dentry: *const c_void,
}

/// Layout fragment of `struct file` (kernel 6.18.7, x86_64). We only declare
/// the fields needed at their authoritative offsets; trailing fields are
/// omitted. The verifier re-types loads against the kernel's BTF, so the
/// truncated Rust layout is fine as long as offsets match.
#[repr(C)]
struct KernelFile {
    _f_lock: [u8; 4],   // spinlock_t (4 bytes in non-debug config)
    f_mode: u32,        // offset 4
    _pad: [u8; 56],     // 8..64 — f_op, f_mapping, ..., f_owner
    f_path: KernelPath, // offset 64 (16 bytes)
}

/// Layout fragment of `struct linux_binprm` (kernel 6.18.7, x86_64). We only
/// care about `file` at offset 64.
#[repr(C)]
struct KernelLinuxBinprm {
    _pad: [u8; 64],
    file: *const KernelFile, // offset 64
}

/// PID -> sentinel. Presence is what matters; the value is unused.
#[map]
static NET_PIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(8192, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[inline(always)]
fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// security_socket_post_create(struct socket *sock, int family, int type,
///                             int protocol, int kern).
/// `family` is a primitive arg, so no struct deref needed.
#[lsm(hook = "socket_post_create", sleepable)]
pub fn socket_post_create(ctx: LsmContext) -> i32 {
    let family: i32 = unsafe { ctx.arg(1) };
    if family != AF_INET && family != AF_INET6 {
        return 0;
    }
    let pid = current_pid();
    let _ = NET_PIDS.insert(&pid, &1u8, 0);
    0
}

/// security_file_open(struct file *file).
#[lsm(hook = "file_open", sleepable)]
pub fn file_open(ctx: LsmContext) -> i32 {
    let pid = current_pid();
    if unsafe { NET_PIDS.get(&pid) }.is_none() {
        return 0;
    }

    let file_ptr: *const KernelFile = unsafe { ctx.arg(0) };
    if file_ptr.is_null() {
        return 0;
    }

    // Direct field load on a trusted kernel pointer. The verifier sees the
    // load against kernel BTF and types it as fmode_t (u32).
    let f_mode = unsafe { (*file_ptr).f_mode };
    if f_mode & FMODE_WRITE == 0 {
        return 0;
    }

    // &(*file_ptr).f_path stays a trusted struct path * for bpf_d_path.
    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    emit_path_event(EVENT_KIND_NETWORK_FILE_OPEN, path_ptr, pid);
    0
}

/// security_bprm_check(struct linux_binprm *bprm).
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let bprm_ptr: *const KernelLinuxBinprm = unsafe { ctx.arg(0) };
    if bprm_ptr.is_null() {
        return 0;
    }

    // Direct field load — verifier types this as trusted_ptr_struct_file.
    let file_ptr = unsafe { (*bprm_ptr).file };
    if file_ptr.is_null() {
        return 0;
    }

    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    emit_path_event(EVENT_KIND_EXECVE, path_ptr, current_pid());
    0
}

/// Reserve an `Event` on the ring buffer; bpf_d_path() fills `filename` with
/// the absolute path of the kernel object behind `path_ptr`.
#[inline(always)]
fn emit_path_event(kind: u32, path_ptr: *mut bpf_path, pid: u32) {
    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(e) => e,
        None => return,
    };
    let p = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<Event>());
        (*p).kind = kind;
        (*p).pid = pid;
        (*p).tgid = bpf_get_current_pid_tgid() as u32;
        if let Ok(c) = bpf_get_current_comm() {
            (*p).comm = c;
        }
        let _ = bpf_d_path(
            path_ptr,
            (*p).filename.as_mut_ptr() as *mut c_char,
            PATH_LEN as u32,
        );
    }
    entry.submit(0);
}

/// Reap NET_PIDS entries when a task exits. Classic tracepoint — mixing
/// tracepoint + LSM programs in the same object is fine.
#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let _ = NET_PIDS.remove(&current_pid());
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

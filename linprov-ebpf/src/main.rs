//! linprov eBPF programs.
//!
//! The model: a PID becomes "network-flagged" once it opens an AF_INET or
//! AF_INET6 socket. Any regular file it subsequently opens for writing is
//! tracked. When the writable FD is closed, we emit an event to userspace
//! which resolves /proc/<pid>/fd/<fd> and applies the provenance xattr.
//!
//! A separate execve tracepoint reports every exec to userspace so the daemon
//! can check the target's xattr and log when a marked file is run.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};
use linprov_common::{Event, EVENT_KIND_EXECVE, EVENT_KIND_NETWORK_FILE_OPEN, PATH_LEN};

/// PID -> open AF_INET/AF_INET6 socket count. LRU because we accept losing
/// state for very old long-lived processes rather than capping new ones.
#[map]
static NET_PIDS: LruHashMap<u32, u32> = LruHashMap::with_max_entries(8192, 0);

/// pid_tgid -> args[0] (socket family) stashed at sys_enter_socket so the
/// matching sys_exit_socket (which carries the returned fd) can check it.
#[map]
static SOCKET_ENTER: HashMap<u64, u64> = HashMap::with_max_entries(2048, 0);

/// pid_tgid -> (flags, filename_ptr) stashed at sys_enter_openat for the
/// matching sys_exit_openat.
#[repr(C)]
#[derive(Copy, Clone)]
struct OpenatArgs {
    flags: u64,
    filename_ptr: u64,
}

#[map]
static OPENAT_ENTER: HashMap<u64, OpenatArgs> = HashMap::with_max_entries(2048, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

const AF_INET: i64 = 2;
const AF_INET6: i64 = 10;

const O_ACCMODE: i64 = 0o3;
const O_WRONLY: i64 = 0o1;
const O_RDWR: i64 = 0o2;

// Tracepoint argument offsets for syscalls/sys_enter_*: after the 16-byte
// common header (incl. __syscall_nr padded to 8), args[N] starts at 16 + 8*N.
// For syscalls/sys_exit_*, the `ret` (long) sits at 16.
const ARG0: usize = 16;
const ARG1: usize = 24;
const ARG2: usize = 32;

#[inline(always)]
fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[tracepoint]
pub fn sys_enter_socket(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let family: u64 = unsafe { ctx.read_at(ARG0) }.unwrap_or(0);
    let _ = SOCKET_ENTER.insert(&pid_tgid, &family, 0);
    0
}

#[tracepoint]
pub fn sys_exit_socket(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let ret: i64 = unsafe { ctx.read_at(ARG0) }.unwrap_or(-1);
    let family = unsafe { SOCKET_ENTER.get(&pid_tgid) }.copied().unwrap_or(0) as i64;
    let _ = SOCKET_ENTER.remove(&pid_tgid);

    if ret < 0 {
        return 0;
    }
    if family != AF_INET && family != AF_INET6 {
        return 0;
    }

    let count = unsafe { NET_PIDS.get(&pid) }.copied().unwrap_or(0);
    let _ = NET_PIDS.insert(&pid, &count.saturating_add(1), 0);
    0
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    let pid = current_pid();
    if unsafe { NET_PIDS.get(&pid) }.is_none() {
        return 0;
    }

    // openat(int dfd, const char *filename, int flags, umode_t mode).
    // Stash both flags and the user-space filename pointer; we need to dereference
    // the pointer at sys_exit_openat (where we also know the resulting fd) so we
    // can emit the event with the filename inline. Reading the path from a
    // /proc/<pid>/fd/<fd> link in userspace races the close syscall and loses.
    let flags: u64 = unsafe { ctx.read_at(ARG2) }.unwrap_or(0);
    let filename_ptr: u64 = unsafe { ctx.read_at(ARG1) }.unwrap_or(0);
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = OpenatArgs { flags, filename_ptr };
    let _ = OPENAT_ENTER.insert(&pid_tgid, &args, 0);
    0
}

#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let args = unsafe { OPENAT_ENTER.get(&pid_tgid) }.copied();
    let _ = OPENAT_ENTER.remove(&pid_tgid);

    let args = match args {
        Some(a) => a,
        None => return 0,
    };

    let ret: i64 = unsafe { ctx.read_at(ARG0) }.unwrap_or(-1);
    if ret < 0 {
        return 0;
    }

    let flags = args.flags as i64;
    let access = flags & O_ACCMODE;
    if access != O_WRONLY && access != O_RDWR {
        return 0;
    }

    let fd = ret as u32;

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(e) => e,
        None => return 0,
    };
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Event>());
        (*ptr).kind = EVENT_KIND_NETWORK_FILE_OPEN;
        (*ptr).pid = pid;
        (*ptr).tgid = pid_tgid as u32;
        (*ptr).fd = fd as i32;
        if let Ok(c) = bpf_get_current_comm() {
            (*ptr).comm = c;
        }
        let filename_slice: &mut [u8] =
            core::slice::from_raw_parts_mut((*ptr).filename.as_mut_ptr(), PATH_LEN);
        let _ =
            bpf_probe_read_user_str_bytes(args.filename_ptr as *const u8, filename_slice);
    }
    entry.submit(0);
    0
}

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let filename_ptr: u64 = match unsafe { ctx.read_at(ARG0) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if filename_ptr == 0 {
        return 0;
    }

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(e) => e,
        None => return 0,
    };
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Event>());
        (*ptr).kind = EVENT_KIND_EXECVE;
        (*ptr).pid = pid;
        (*ptr).tgid = pid_tgid as u32;
        if let Ok(c) = bpf_get_current_comm() {
            (*ptr).comm = c;
        }
        let filename_slice: &mut [u8] =
            core::slice::from_raw_parts_mut((*ptr).filename.as_mut_ptr(), PATH_LEN);
        let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, filename_slice);
    }
    entry.submit(0);
    0
}

/// We hook execveat too so we catch fexecve()-style calls. Layout matches
/// execve except args[1] is the filename pointer (args[0] is dfd).
#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // execveat(int dfd, const char *filename, ..., int flags)
    let filename_ptr: u64 = match unsafe { ctx.read_at(ARG0 + 8) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    if filename_ptr == 0 {
        return 0;
    }

    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(e) => e,
        None => return 0,
    };
    let ptr = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Event>());
        (*ptr).kind = EVENT_KIND_EXECVE;
        (*ptr).pid = pid;
        (*ptr).tgid = pid_tgid as u32;
        if let Ok(c) = bpf_get_current_comm() {
            (*ptr).comm = c;
        }
        let filename_slice: &mut [u8] =
            core::slice::from_raw_parts_mut((*ptr).filename.as_mut_ptr(), PATH_LEN);
        let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, filename_slice);
    }
    entry.submit(0);
    0
}

#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid = current_pid();
    let _ = NET_PIDS.remove(&pid);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

//! linprov eBPF programs (BPF LSM + kfunc edition).
//!
//! Same model as the LSM-only version, but now both the xattr write and the
//! xattr read happen in-kernel via kfuncs (`bpf_set_dentry_xattr`,
//! `bpf_get_file_xattr`). Userspace only sees ringbuf events for logging.
//!
//! Kfunc resolution is handled by our aya fork — see the `relocate_kfuncs`
//! step in aya-obj. The `extern "C"` declarations below compile to
//! `call -1` placeholders that aya patches to `BPF_PSEUDO_KFUNC_CALL`
//! against the kernel's BTF at load time.
//!
//! Struct layouts are pinned to kernel 6.18 / x86_64.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use core::mem::MaybeUninit;

use aya_ebpf::{
    bindings::{bpf_dynptr, path as bpf_path},
    cty::{c_char, c_void},
    helpers::{
        bpf_dynptr_from_mem, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_ktime_get_boot_ns,
    },
    macros::{lsm, map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use linprov_common::{
    Event, OriginRecord, EVENT_KIND_EXECVE, EVENT_KIND_NETWORK_FILE_OPEN, PATH_LEN,
};

// Kernel kfuncs. Resolved at load time by the patched aya: the unresolved
// symbols below produce R_BPF_64_32 relocations against `call -1`
// placeholders, which `Object::relocate_kfuncs` rewrites into
// `BPF_PSEUDO_KFUNC_CALL` with the kernel BTF id.
//
// The `link_section = ".ksyms"` annotation mirrors libbpf's `__ksym` macro —
// without it the LLVM BPF backend treats the extern call as a generic subprog
// and skips emitting the helper-style arg setup (r1..r5).
//
// NB: `bpf_set_dentry_xattr` carries `KF_TRUSTED_ARGS`, and the dentry we get
// via `file->f_path.dentry` lands in the verifier as `untrusted_ptr_dentry`
// (struct path's `dentry` field isn't in the BTF safe-trusted list). Until we
// find a way to materialize a trusted dentry, the xattr WRITE stays on the
// userspace side and we only do the in-kernel READ here.
extern "C" {
    fn bpf_get_file_xattr(
        file: *mut c_void,
        name: *const c_char,
        value: *mut bpf_dynptr,
    ) -> i32;
}

/// Wrap the kfunc call in inline assembly that explicitly materializes the
/// args into r1..r3. The bare `extern "C"` call emits a `call -1` placeholder
/// without arg setup — the LLVM-BPF backend assumes the registers already
/// hold the right values, which they don't after a prior `bpf_dynptr_from_mem`
/// helper has clobbered r1..r5.
#[inline(always)]
unsafe fn call_get_file_xattr(
    file: *mut c_void,
    name: *const c_char,
    value: *mut bpf_dynptr,
) -> i32 {
    let ret: i64;
    core::arch::asm!(
        "call {kfunc}",
        kfunc = sym bpf_get_file_xattr,
        inout("r1") file => _,
        inout("r2") name => _,
        inout("r3") value => _,
        lateout("r0") ret,
        out("r4") _,
        out("r5") _,
        options(nostack),
    );
    ret as i32
}

// Helper 147; aya doesn't re-export it.
#[inline(always)]
unsafe fn bpf_d_path(p: *mut bpf_path, buf: *mut c_char, sz: u32) -> i64 {
    let fun: unsafe extern "C" fn(*mut bpf_path, *mut c_char, u32) -> i64 =
        core::mem::transmute(147usize);
    fun(p, buf, sz)
}

const XATTR_NAME_C: &[u8] = b"security.bpf.linprov.origin\0";

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

const FMODE_WRITE: u32 = 0x2;

#[repr(C)]
struct KernelPath {
    _mnt: *const c_void,
    dentry: *mut c_void, // struct dentry *
}

#[repr(C)]
struct KernelFile {
    _f_lock: [u8; 4],
    f_mode: u32,
    _pad: [u8; 56],
    f_path: KernelPath,
}

#[repr(C)]
struct KernelLinuxBinprm {
    _pad: [u8; 64],
    file: *const KernelFile,
}

#[map]
static NET_PIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(8192, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Per-CPU scratch buffer for the OriginRecord we pass to / receive from the
/// xattr kfuncs. The verifier rejects stack memory as `bpf_dynptr_from_mem`'s
/// data arg — it requires a map value or ringbuf reservation. Per-CPU keeps
/// it concurrency-safe: BPF runtime guarantees no recursive invocation of
/// the same program on a single CPU, so even with sleepable kfunc calls in
/// the middle, this slot belongs to us until we return.
#[map]
static SCRATCH: PerCpuArray<OriginRecord> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[inline(always)]
fn current_comm() -> [u8; 16] {
    bpf_get_current_comm().unwrap_or([0u8; 16])
}

/// security_socket_post_create(struct socket *sock, int family, int type,
///                             int protocol, int kern).
#[lsm(hook = "socket_post_create", sleepable)]
pub fn socket_post_create(ctx: LsmContext) -> i32 {
    let family: i32 = unsafe { ctx.arg(1) };
    if family != AF_INET && family != AF_INET6 {
        return 0;
    }
    let _ = NET_PIDS.insert(&current_pid(), &1u8, 0);
    0
}

/// security_file_open(struct file *file).
///
/// We can't yet do the xattr write in-kernel (see the comment on the kfunc
/// extern block), so this still emits a ringbuf event with the path and lets
/// userspace setxattr.
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

    let f_mode = unsafe { (*file_ptr).f_mode };
    if f_mode & FMODE_WRITE == 0 {
        return 0;
    }

    let rec = OriginRecord {
        version: 1,
        pid,
        ts_boot_ns: unsafe { bpf_ktime_get_boot_ns() },
        comm: current_comm(),
    };
    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    emit_event(EVENT_KIND_NETWORK_FILE_OPEN, path_ptr, pid, &rec, 0);
    0
}

/// security_bprm_check(struct linux_binprm *bprm).
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let bprm_ptr: *const KernelLinuxBinprm = unsafe { ctx.arg(0) };
    if bprm_ptr.is_null() {
        return 0;
    }

    let file_ptr = unsafe { (*bprm_ptr).file };
    if file_ptr.is_null() {
        return 0;
    }

    // Per-CPU scratch buffer for the kfunc to write the xattr value into.
    let buf = match SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, core::mem::size_of::<OriginRecord>());
    }

    let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();
    let r = unsafe {
        bpf_dynptr_from_mem(
            buf as *mut c_void,
            core::mem::size_of::<OriginRecord>() as u32,
            0,
            dynptr.as_mut_ptr(),
        )
    };
    if r != 0 {
        return 0;
    }

    let get_ret = unsafe {
        call_get_file_xattr(
            file_ptr as *mut c_void,
            XATTR_NAME_C.as_ptr() as *const c_char,
            dynptr.as_mut_ptr(),
        )
    };
    if get_ret < 0 {
        // No xattr (or unreadable namespace) — every exec hits this path so
        // we don't bother emitting an event for it.
        return 0;
    }

    let rec = unsafe { *buf };
    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    emit_event(EVENT_KIND_EXECVE, path_ptr, current_pid(), &rec, get_ret);
    0
}

/// Reserve an `Event` on the ring buffer and have bpf_d_path() fill in the
/// filename. Embeds the origin record so userspace doesn't have to retrieve
/// it again.
#[inline(always)]
fn emit_event(
    kind: u32,
    path_ptr: *mut bpf_path,
    pid: u32,
    origin: &OriginRecord,
    status: i32,
) {
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
        (*p).status = status;
        (*p).comm = current_comm();
        (*p).origin = *origin;
        let _ = bpf_d_path(
            path_ptr,
            (*p).filename.as_mut_ptr() as *mut c_char,
            PATH_LEN as u32,
        );
    }
    entry.submit(0);
}

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

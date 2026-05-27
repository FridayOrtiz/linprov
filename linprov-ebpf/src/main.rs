//! linprov eBPF programs (BPF LSM + kfunc + inode_storage edition).
//!
//! Two mark sources, both maintained in-kernel:
//!
//!   * INODE_MARKS — a BPF_MAP_TYPE_INODE_STORAGE map keyed on
//!     `struct inode *`. Written synchronously in `file_open` the instant
//!     a network-touched PID opens a file for write. No race window
//!     between the LSM hook returning and the next execve hitting the
//!     same inode. Lifetime is until the inode is evicted from cache.
//!   * security.bpf.linprov.origin xattr — persistent across reboots
//!     and inode eviction. Written by userspace (off the ringbuf event)
//!     because `bpf_set_dentry_xattr` carries `KF_TRUSTED_ARGS` and
//!     `file->f_path.dentry` isn't on the verifier's safe-trusted list,
//!     so we can't issue the write from `file_open` in-kernel. Read
//!     in-kernel via `bpf_get_file_xattr` as the fallback source.
//!
//! `bprm_check_security` consults INODE_MARKS first, then falls back to
//! the xattr. Either source produces an OriginRecord; downstream
//! enforce/log handling doesn't care which.
//!
//! Kfunc resolution is handled by our aya fork — see the `relocate_kfuncs`
//! step in aya-obj. The `extern "C"` declaration below compiles to a
//! `call -1` placeholder that aya patches to `BPF_PSEUDO_KFUNC_CALL`
//! against the kernel's BTF at load time.
//!
//! Struct layouts are pinned to kernel 6.18 / x86_64.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use core::mem::MaybeUninit;

use aya_ebpf::{
    bindings::{bpf_dynptr, path as bpf_path},
    btf_maps::InodeStorage,
    cty::{c_char, c_void},
    helpers::{
        bpf_dynptr_from_mem, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_ktime_get_boot_ns,
    },
    macros::{btf_map, lsm, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use linprov_common::{
    Event, OriginRecord, EVENT_KIND_EXECVE, EVENT_KIND_NETWORK_FILE_OPEN, MODE_ENFORCE, PATH_LEN,
};

// Kernel kfunc. Resolved at load time by the patched aya: the unresolved
// symbol below produces an R_BPF_64_32 relocation against a `call -1`
// placeholder, which `Object::relocate_kfuncs` rewrites into
// `BPF_PSEUDO_KFUNC_CALL` with the kernel BTF id.
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
    _f_lock: [u8; 4],            // 0..4    spinlock_t f_lock
    f_mode: u32,                 // 4..8    fmode_t f_mode
    _pad_pre_inode: [u8; 24],    // 8..32   f_op, f_mapping, private_data
    f_inode: *mut c_void,        // 32..40  struct inode *f_inode
    _pad_post_inode: [u8; 24],   // 40..64  f_flags, f_iocb_flags, f_cred, f_owner
    f_path: KernelPath,          // 64..80  const struct path f_path
}

#[repr(C)]
struct KernelLinuxBinprm {
    _pad: [u8; 64],
    file: *const KernelFile,
}

#[map]
static NET_PIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(8192, 0);

/// Per-inode provenance mark. Written in `file_open` the moment a
/// network-touched PID opens a file for write; read first in
/// `bprm_check_security` before falling back to the on-disk xattr.
///
/// The inode-storage path closes the race window between the file_open hook
/// returning and userspace getting around to writing the xattr — we can
/// enforce on the freshly-downloaded inode the very next instant. The xattr
/// is the durability layer: it survives reboots and inode eviction; this
/// map handles the same boot.
#[btf_map]
static INODE_MARKS: InodeStorage<OriginRecord> = InodeStorage::new();

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

/// Runtime mode set by userspace before attach. Index 0 holds a value from
/// the `MODE_*` constants in `linprov_common`.
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

/// Allowlist of absolute paths (PATH_LEN-byte keys, NUL-padded) that
/// `bprm_check_security` will permit when running in `MODE_ENFORCE`. Paths
/// not present are blocked with -EPERM. Populated by userspace at startup
/// and incrementally extended in soak mode.
#[map]
static ALLOWLIST: HashMap<[u8; PATH_LEN], u8> = HashMap::with_max_entries(4096, 0);

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
/// Writes the OriginRecord into INODE_MARKS for the in-kernel fast path,
/// and emits a ringbuf event so userspace can persist the same record as
/// an xattr (durability layer).
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

    let mut rec = OriginRecord {
        version: 1,
        pid,
        ts_boot_ns: unsafe { bpf_ktime_get_boot_ns() },
        comm: current_comm(),
    };

    // In-kernel mark: write the OriginRecord into inode storage right now.
    // bprm_check_security can then enforce on this inode without waiting on
    // userspace to land the xattr. Best-effort; if storage allocation fails
    // we still emit the ringbuf event and fall through to the xattr path.
    let inode_ptr = unsafe { (*file_ptr).f_inode };
    if !inode_ptr.is_null() {
        let _ = unsafe { INODE_MARKS.get_or_insert_ptr(inode_ptr, &mut rec as *mut _) };
    }

    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    emit_event(EVENT_KIND_NETWORK_FILE_OPEN, path_ptr, pid, &rec, 0);
    0
}

/// security_bprm_check(struct linux_binprm *bprm, int retval).
///
/// LSM hooks see the previous LSM's verdict in `retval` (last BTF arg). If
/// somebody already said no, we preserve that — never silently re-enable an
/// exec that landlock/apparmor blocked.
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let retval: i32 = unsafe { ctx.arg(1) };
    if retval != 0 {
        return retval;
    }

    let bprm_ptr: *const KernelLinuxBinprm = unsafe { ctx.arg(0) };
    if bprm_ptr.is_null() {
        return 0;
    }

    let file_ptr = unsafe { (*bprm_ptr).file };
    if file_ptr.is_null() {
        return 0;
    }

    let buf = match SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, core::mem::size_of::<OriginRecord>());
    }

    // Two mark sources, checked in order:
    //
    //   1. INODE_MARKS — populated synchronously by file_open in the same
    //      boot. Fast (one map lookup) and race-free for freshly-marked
    //      files: the userspace xattr round-trip hasn't necessarily landed
    //      yet by the time the exec hook fires.
    //   2. security.bpf.linprov.origin xattr — durable across reboots and
    //      inode eviction. Costlier (dynptr + kfunc into the FS layer) but
    //      the only source that survives if the inode got dropped from
    //      cache or the file was carried over from a previous boot.
    //
    // Either source produces an OriginRecord; the rest of the handler doesn't
    // care which.
    let inode_ptr = unsafe { (*file_ptr).f_inode };
    let mut marked = false;
    if !inode_ptr.is_null() {
        if let Some(stored) = unsafe { INODE_MARKS.get_ptr(inode_ptr) } {
            unsafe { core::ptr::copy_nonoverlapping(stored, buf, 1) };
            marked = true;
        }
    }

    if !marked {
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
            // Unmarked from both sources — every exec hits this path; no
            // event, no enforcement.
            return 0;
        }
    }

    // Marked. Resolve the path into a freshly-reserved ringbuf entry, then
    // use that buffer as the allowlist key. The same memory carries the
    // event to userspace once we submit.
    let rec = unsafe { *buf };
    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(e) => e,
        None => return 0,
    };
    let p = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<Event>());
        (*p).kind = EVENT_KIND_EXECVE;
        (*p).pid = current_pid();
        (*p).tgid = bpf_get_current_pid_tgid() as u32;
        (*p).comm = current_comm();
        (*p).origin = rec;
        let _ = bpf_d_path(
            path_ptr,
            (*p).filename.as_mut_ptr() as *mut c_char,
            PATH_LEN as u32,
        );
    }

    let mode = CONFIG.get(0).copied().unwrap_or(0);
    let on_list = unsafe { ALLOWLIST.get(&(*p).filename) }.is_some();
    let decision: i32 = if mode == MODE_ENFORCE && !on_list { -1 } else { 0 };
    unsafe {
        (*p).status = decision;
    }
    entry.submit(0);
    decision
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

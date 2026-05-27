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
        bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
    },
    macros::{btf_map, lsm, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use linprov_common::{
    dim, AllowRule, Event, OriginRecord, COMM_LEN, EVENT_KIND_EXECVE,
    EVENT_KIND_NETWORK_FILE_OPEN, FNV_OFFSET, FNV_PRIME, MAX_FOLDER_HASHES, MAX_RULES,
    MODE_ENFORCE, ORIGIN_VERSION, PATH_HASH_SCAN_LEN, PATH_LEN,
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

/// Per-CPU scratch buffers for the OriginRecord. Slot 0 is owned by
/// `file_open` (the producing program); slot 1 by `bprm_check_security`.
/// Two slots because both hooks can be running on the same CPU during a
/// sleepable kfunc yield — separate slots avoid corruption.
///
/// Map value-ptrs are required by `bpf_dynptr_from_mem` (it rejects stack
/// memory), and the kernel guarantees no recursive invocation of the same
/// program on a single CPU, so within one program the slot is stable
/// across sleepable calls.
#[map]
static SCRATCH: PerCpuArray<OriginRecord> = PerCpuArray::with_max_entries(2, 0);

const SCRATCH_FILE_OPEN: u32 = 0;
const SCRATCH_BPRM: u32 = 1;


/// Runtime mode set by userspace before attach. Index 0 holds a value from
/// the `MODE_*` constants in `linprov_common`.
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

// ------ Allowlist rules. One slot per rule; each rule is an AND of
// (dim, value) conditions. Rules OR together (first fully-matching rule
// permits). Populated by userspace at startup; incrementally extended
// in soak mode.

#[map]
static ALLOW_RULES: Array<AllowRule> = Array::with_max_entries(MAX_RULES as u32, 0);

/// Number of valid entries at the front of `ALLOW_RULES`. Index 0.
#[map]
static ALLOW_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

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
/// an xattr (durability layer) — including the creator's full exe path,
/// which BPF can't easily resolve here.
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

    let rec_ptr = match SCRATCH.get_ptr_mut(SCRATCH_FILE_OPEN) {
        Some(p) => p,
        None => return 0,
    };
    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    unsafe {
        // Zero everything first so creator_path (filled by userspace later)
        // starts clean — bprm_check_security uses `creator_path[0] == 0` as
        // the "not yet augmented" signal.
        core::ptr::write_bytes(rec_ptr as *mut u8, 0, core::mem::size_of::<OriginRecord>());
        (*rec_ptr).version = ORIGIN_VERSION;
        (*rec_ptr).pid = pid;
        (*rec_ptr).ts_boot_ns = bpf_ktime_get_boot_ns();
        (*rec_ptr).comm = current_comm();
        (*rec_ptr).creator_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
        // landing_filename: where the file is being written right now.
        // Distinct from the eventual exec-time path (the file may be
        // renamed before execve); the record carries this through.
        let _ = bpf_d_path(
            path_ptr,
            (*rec_ptr).landing_filename.as_mut_ptr() as *mut c_char,
            PATH_LEN as u32,
        );
        // creator_path stays all-zero. Userspace reads /proc/$pid/exe and
        // writes the augmented record into the xattr.
    }

    // In-kernel mark: write the OriginRecord into inode storage right now.
    // bprm_check_security can then enforce on this inode without waiting on
    // userspace to land the xattr.
    let inode_ptr = unsafe { (*file_ptr).f_inode };
    if !inode_ptr.is_null() {
        let _ = unsafe { INODE_MARKS.get_or_insert_ptr(inode_ptr, rec_ptr) };
    }

    emit_event(EVENT_KIND_NETWORK_FILE_OPEN, path_ptr, pid, rec_ptr, 0);
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

    let buf = match SCRATCH.get_ptr_mut(SCRATCH_BPRM) {
        Some(p) => p,
        None => return 0,
    };
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, core::mem::size_of::<OriginRecord>());
    }

    // Two mark sources:
    //
    //   1. INODE_MARKS — populated synchronously by file_open. Fast and
    //      race-free for same-boot freshly-marked files. May hold a partial
    //      record (creator_path empty) if userspace hasn't yet read
    //      /proc/$pid/exe; we fall through to the xattr in that case to
    //      try for a more complete record.
    //   2. security.bpf.linprov.origin xattr — durable across reboots and
    //      inode eviction. Always written with the augmented record
    //      (creator_path filled) by userspace.
    let inode_ptr = unsafe { (*file_ptr).f_inode };
    let mut have_storage = false;
    if !inode_ptr.is_null() {
        if let Some(stored) = unsafe { INODE_MARKS.get_ptr(inode_ptr) } {
            unsafe { core::ptr::copy_nonoverlapping(stored, buf, 1) };
            have_storage = true;
        }
    }

    // Try xattr if there's no storage record, or storage was partial.
    let need_xattr = !have_storage || unsafe { (*buf).creator_path[0] == 0 };
    let mut have_xattr = false;
    if need_xattr {
        let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();
        let r = unsafe {
            bpf_dynptr_from_mem(
                buf as *mut c_void,
                core::mem::size_of::<OriginRecord>() as u32,
                0,
                dynptr.as_mut_ptr(),
            )
        };
        if r == 0 {
            let get_ret = unsafe {
                call_get_file_xattr(
                    file_ptr as *mut c_void,
                    XATTR_NAME_C.as_ptr() as *const c_char,
                    dynptr.as_mut_ptr(),
                )
            };
            have_xattr = get_ret >= 0;
        }
    }

    // If xattr was missing and storage was empty, the file isn't marked.
    // If xattr was missing but storage gave us a partial record, the
    // `bpf_get_file_xattr` failure leaves buf untouched (kfunc only writes
    // on success), so we still have the storage copy.
    if !have_xattr && !have_storage {
        return 0;
    }

    // Schema version gate. We deliberately ignore v1 records — old daemons
    // wrote a smaller layout; without the gate we'd interpret comm bytes
    // as creator_uid, etc.
    if unsafe { (*buf).version } != ORIGIN_VERSION {
        return 0;
    }

    // Resolve the path into a freshly-reserved ringbuf entry. We avoid any
    // local-by-value copy of the OriginRecord — at 296 bytes it blows the
    // BPF stack — by always going via map pointers (`buf`) or the ringbuf
    // entry pointer (`p`).
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
        // map → ringbuf copy, no stack temporary
        core::ptr::copy_nonoverlapping(buf, &mut (*p).origin as *mut OriginRecord, 1);
        let _ = bpf_d_path(
            path_ptr,
            (*p).filename.as_mut_ptr() as *mut c_char,
            PATH_LEN as u32,
        );
    }

    let mode = CONFIG.get(0).copied().unwrap_or(0);
    let permit = if mode == MODE_ENFORCE {
        unsafe { check_allowlist(&(*p).filename, &(*p).origin) }
    } else {
        true
    };
    let decision: i32 = if !permit { -1 } else { 0 };
    unsafe {
        (*p).status = decision;
    }
    entry.submit(0);
    decision
}

#[inline(always)]
fn comm_eq(a: &[u8; COMM_LEN], b: &[u8; COMM_LEN]) -> bool {
    let mut eq = true;
    for i in 0..COMM_LEN {
        if a[i] != b[i] {
            eq = false;
        }
    }
    eq
}

/// FNV-1a-64 of a NUL-terminated path. Scans up to
/// [`PATH_HASH_SCAN_LEN`] bytes.
#[inline(always)]
fn fnv_full(src: *const u8) -> u64 {
    let mut hash: u64 = FNV_OFFSET;
    for i in 0..PATH_HASH_SCAN_LEN {
        let b = unsafe { *src.add(i) };
        if b == 0 {
            break;
        }
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// True if `needle` equals the FNV-1a hash of any `/`-terminated prefix
/// of the NUL-terminated path at `src`. Walks the path once, checking
/// at each separator; no folder-hash array materialization (which blows
/// the verifier's per-instruction state budget).
#[inline(always)]
fn folder_match(src: *const u8, needle: u64) -> bool {
    let mut hash: u64 = FNV_OFFSET;
    let mut found = false;
    for i in 0..PATH_HASH_SCAN_LEN {
        let b = unsafe { *src.add(i) };
        if b == 0 {
            break;
        }
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        if b == b'/' && hash == needle {
            found = true;
        }
    }
    found
}

/// Returns true if any allowlist rule's conditions all match. Rules OR
/// together; within a rule, dim conditions AND.
///
/// Path-shaped dims (`*_filename`, `*_folder`) compute their hashes
/// **per rule, on demand** rather than pre-computing into a stack array
/// — pre-computation with conditional stores at `/` positions exploded
/// the verifier's per-instruction state space. Re-walking per rule is
/// O(MAX_RULES × PATH_HASH_SCAN_LEN), but with simpler control flow the
/// verifier can prune state much more aggressively.
#[inline(always)]
unsafe fn check_allowlist(filename: &[u8; PATH_LEN], origin: &OriginRecord) -> bool {
    let count = ALLOW_RULE_COUNT.get(0).copied().unwrap_or(0);
    if count == 0 {
        return false;
    }
    let exec_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;

    let n = if count as usize > MAX_RULES { MAX_RULES as u32 } else { count };
    for i in 0..MAX_RULES {
        if (i as u32) >= n {
            break;
        }
        let rule = match ALLOW_RULES.get(i as u32) {
            Some(r) => r,
            None => break,
        };
        let f = rule.flags;
        if f == 0 {
            continue;
        }

        // Cheapest dims first; bail out before the path walks if any of
        // the scalar checks fail.
        if (f & dim::CREATOR_UID) != 0 && rule.creator_uid != origin.creator_uid {
            continue;
        }
        if (f & dim::EXECUTION_UID) != 0 && rule.execution_uid != exec_uid {
            continue;
        }
        if (f & dim::CREATOR_COMM) != 0 && !comm_eq(&rule.creator_comm, &origin.comm) {
            continue;
        }
        if (f & dim::CREATOR_PROCESS) != 0 {
            if origin.creator_path[0] == 0
                || fnv_full(origin.creator_path.as_ptr()) != rule.creator_process_hash
            {
                continue;
            }
        }
        if (f & dim::TARGET_FILENAME) != 0
            && fnv_full(filename.as_ptr()) != rule.target_filename_hash
        {
            continue;
        }
        if (f & dim::LANDING_FILENAME) != 0
            && fnv_full(origin.landing_filename.as_ptr()) != rule.landing_filename_hash
        {
            continue;
        }
        if (f & dim::TARGET_FOLDER) != 0
            && !folder_match(filename.as_ptr(), rule.target_folder_hash)
        {
            continue;
        }
        if (f & dim::LANDING_FOLDER) != 0
            && !folder_match(origin.landing_filename.as_ptr(), rule.landing_folder_hash)
        {
            continue;
        }
        return true;
    }
    false
}

// MAX_FOLDER_HASHES is no longer used by BPF — the per-rule walk
// doesn't need a precomputed array — but the constant stays in
// linprov-common for the userspace check.
#[allow(dead_code)]
const _MAX_FOLDER_HASHES_REFERENCE: usize = MAX_FOLDER_HASHES;

/// Reserve an `Event` on the ring buffer and have bpf_d_path() fill in the
/// filename. Embeds the origin record so userspace doesn't have to retrieve
/// it again.
#[inline(always)]
fn emit_event(
    kind: u32,
    path_ptr: *mut bpf_path,
    pid: u32,
    origin: *const OriginRecord,
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

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
        bpf_get_current_uid_gid, bpf_ktime_get_boot_ns, bpf_probe_read_kernel,
    },
    macros::{btf_map, lsm, map, tracepoint},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use linprov_common::{
    dim, AllowRule, Event, OriginRecord, COMM_LEN, EVENT_KIND_DERIVED_FILE_OPEN, EVENT_KIND_EXECVE,
    EVENT_KIND_NETWORK_FILE_OPEN, EXEC_PATH_LEN, FNV_OFFSET, FNV_PRIME, MAX_FOLDER_ANCESTORS,
    MAX_RULES, MODE_ENFORCE, ORIGIN_VERSION, PATH_HASH_SCAN_LEN,
};

// Kernel kfunc. Resolved at load time by the patched aya: the unresolved
// symbol below produces an R_BPF_64_32 relocation against a `call -1`
// placeholder, which `Object::relocate_kfuncs` rewrites into
// `BPF_PSEUDO_KFUNC_CALL` with the kernel BTF id.
extern "C" {
    fn bpf_get_file_xattr(file: *mut c_void, name: *const c_char, value: *mut bpf_dynptr) -> i32;
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

/// BPF program license. The kernel inspects the `license` ELF section
/// when loading; programs that don't claim a GPL-compatible license
/// can't call `gpl_only` helpers (we rely on `bpf_d_path`, which is one
/// of them). Dual-licensing matches the userspace crate's
/// `MIT OR Apache-2.0` while still presenting a GPL token to the
/// kernel verifier.
#[link_section = "license"]
#[no_mangle]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

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
    _f_lock: [u8; 4],          // 0..4    spinlock_t f_lock
    f_mode: u32,               // 4..8    fmode_t f_mode
    _pad_pre_inode: [u8; 24],  // 8..32   f_op, f_mapping, private_data
    f_inode: *mut c_void,      // 32..40  struct inode *f_inode
    _pad_post_inode: [u8; 24], // 40..64  f_flags, f_iocb_flags, f_cred, f_owner
    f_path: KernelPath,        // 64..80  const struct path f_path
}

#[repr(C)]
struct KernelLinuxBinprm {
    _pad: [u8; 64],
    file: *const KernelFile,
}

#[map]
static NET_PIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(8192, 0);

/// PIDs tainted by **reading** a marked inode (same-boot, via INODE_MARKS).
/// The value is the source file's `OriginRecord`: files this PID
/// subsequently writes inherit it (with their own landing hashes), so a
/// `tar`/`unzip`/`cp` of a marked file propagates the mark to its outputs.
/// Reaped on task exit alongside `NET_PIDS`.
#[map]
static PROP_PIDS: LruHashMap<u32, OriginRecord> = LruHashMap::with_max_entries(8192, 0);

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

/// A `PATH_MAX`-sized byte buffer; map value type for [`PATH_SCRATCH`].
/// Wrapper struct so it's a single named map value.
#[repr(C)]
#[derive(Clone, Copy)]
struct PathScratch([u8; EXEC_PATH_LEN]);

/// Per-CPU scratch for the landing path in `file_open`: `bpf_d_path`
/// resolves into here, then [`landing_hashes`] walks it. Separate from
/// the ringbuf event's filename buffer (which `emit_event` fills
/// independently) and big enough for any path the kernel can name.
#[map]
static PATH_SCRATCH: PerCpuArray<PathScratch> = PerCpuArray::with_max_entries(1, 0);

/// Runtime config set by userspace before attach.
///   Index 0: a value from the `MODE_*` constants in `linprov_common`.
///   Index 1: non-zero to mark PIDs that connect to a loopback address
///            (default is to skip loopback so local dev / package
///            mirrors on 127.0.0.1 don't litter the allowlist).
///   Index 2: the daemon's own PID. The read-taint branch skips it so the
///            daemon — which opens marked files to back-fill INODE_MARKS —
///            never taints itself and marks its own log/db/allowlist writes.
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(3, 0);

const CONFIG_MODE: u32 = 0;
const CONFIG_MARK_LOCALHOST: u32 = 1;
const CONFIG_SELF_PID: u32 = 2;

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

// sockaddr layout, family-specific. We only need the address bytes —
// port / flow / scope are uninteresting.

#[repr(C)]
struct KernelSockAddr {
    sa_family: u16,
    _data: [u8; 14],
}

#[repr(C)]
struct KernelSockAddrIn {
    sin_family: u16,
    _sin_port: u16,
    /// Stored network byte order. On little-endian BPF target the low
    /// byte of the host-loaded u32 is the first BE byte (i.e. the `127`
    /// in `127.x.y.z`).
    sin_addr: u32,
    _sin_zero: [u8; 8],
}

#[repr(C)]
struct KernelSockAddrIn6 {
    sin6_family: u16,
    _sin6_port: u16,
    _sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    _sin6_scope_id: u32,
}

#[inline(always)]
fn is_v4_loopback(addr: *const KernelSockAddrIn) -> bool {
    // 127.0.0.0/8 — first BE byte is 127. sin_addr at offset 4 is
    // within `struct sockaddr`'s 16-byte verifier window, so a
    // direct read is fine.
    let v = unsafe { (*addr).sin_addr };
    (v & 0xff) == 127
}

#[inline(always)]
fn is_v6_loopback(addr: *const KernelSockAddrIn6) -> bool {
    // sin6_addr starts at offset 8 and is 16 bytes long, which puts
    // the tail at offset 24 — past the verifier-enforced
    // `struct sockaddr` window. Use bpf_probe_read_kernel to grab
    // the bytes into an on-stack buffer.
    let src = unsafe { &(*addr).sin6_addr } as *const [u8; 16];
    let bytes: [u8; 16] = match unsafe { bpf_probe_read_kernel(src) } {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut ok = bytes[15] == 1;
    for &b in bytes.iter().take(15) {
        if b != 0 {
            ok = false;
        }
    }
    ok
}

/// security_socket_connect(struct socket *sock, struct sockaddr *address,
///                         int addrlen).
///
/// Marks the PID as network-touched when it connects to a non-loopback
/// address. Loopback connects (`127.0.0.0/8`, `::1`) are ignored by
/// default — flip `CONFIG[CONFIG_MARK_LOCALHOST]` to non-zero to
/// include them (e.g. for the smoke tests that download from a local
/// python `http.server`).
#[lsm(hook = "socket_connect", sleepable)]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    let retval: i32 = ctx.arg(3);
    if retval != 0 {
        return retval;
    }

    let addr_ptr: *const KernelSockAddr = ctx.arg(1);
    if addr_ptr.is_null() {
        return 0;
    }
    let family = unsafe { (*addr_ptr).sa_family } as i32;

    let mark_localhost = CONFIG.get(CONFIG_MARK_LOCALHOST).copied().unwrap_or(0) != 0;

    let is_loopback = if family == AF_INET {
        is_v4_loopback(addr_ptr as *const KernelSockAddrIn)
    } else if family == AF_INET6 {
        is_v6_loopback(addr_ptr as *const KernelSockAddrIn6)
    } else {
        return 0; // not an internet family — ignore
    };

    if is_loopback && !mark_localhost {
        return 0;
    }

    let _ = NET_PIDS.insert(current_pid(), 1u8, 0);
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

    let file_ptr: *const KernelFile = ctx.arg(0);
    if file_ptr.is_null() {
        return 0;
    }
    let inode_ptr = unsafe { (*file_ptr).f_inode };
    let f_mode = unsafe { (*file_ptr).f_mode };

    // --- Read branch: taint the reader if it opened a marked inode. ---
    //
    // Runs on every non-write open (the kernel's hottest path), so it does
    // only a single cheap INODE_MARKS lookup — same-boot propagation only,
    // no xattr read here. A process that reads a marked file is recorded in
    // PROP_PIDS carrying the source's OriginRecord; files it later writes
    // inherit it (the write branch below). This is what makes `tar`/`unzip`
    // of a marked archive — and `cp` of a marked file — propagate the mark.
    //
    // The daemon is excluded: it opens marked files (O_PATH) to back-fill
    // INODE_MARKS with the augmented record, and must never taint itself
    // and start marking its own log / hashdb / allowlist writes.
    if f_mode & FMODE_WRITE == 0 {
        let self_pid = CONFIG.get(CONFIG_SELF_PID).copied().unwrap_or(0);
        if pid != self_pid && !inode_ptr.is_null() {
            if let Some(stored) = unsafe { INODE_MARKS.get_ptr(inode_ptr) } {
                // Pass the value BY REFERENCE: `insert` forwards the `&V`
                // straight to bpf_map_update_elem, so this updates from the
                // INODE_MARKS storage pointer with no 320-byte by-value copy
                // on the BPF stack. clippy's "simplify `&*stored` to
                // `*stored`" would reintroduce exactly that stack copy, so
                // the lint is suppressed here deliberately.
                #[allow(clippy::needless_borrows_for_generic_args)]
                let _ = PROP_PIDS.insert(pid, unsafe { &*stored }, 0);
            }
        }
        return 0;
    }

    // --- Write branch: mark the output if the writer is a mark source. ---
    let rec_ptr = match SCRATCH.get_ptr_mut(SCRATCH_FILE_OPEN) {
        Some(p) => p,
        None => return 0,
    };

    // Two mark sources, in priority order:
    //   * network-touched (NET_PIDS) → fresh record naming this process as
    //     creator (creator_path_hash left 0 for userspace to augment);
    //   * taint-propagating (PROP_PIDS) → inherit the source file's record
    //     verbatim (creator identity, ts, and creator_path_hash if userspace
    //     already back-filled it). Landing hashes are overwritten below.
    // Neither → not a mark source; nothing to do.
    let kind = if unsafe { NET_PIDS.get(pid) }.is_some() {
        unsafe {
            // Zero first so creator_path_hash (filled by userspace later)
            // starts at 0 — bprm_check_security uses `creator_path_hash == 0`
            // as the "not yet augmented" signal.
            core::ptr::write_bytes(rec_ptr as *mut u8, 0, core::mem::size_of::<OriginRecord>());
            (*rec_ptr).version = ORIGIN_VERSION;
            (*rec_ptr).pid = pid;
            (*rec_ptr).ts_boot_ns = bpf_ktime_get_boot_ns();
            (*rec_ptr).comm = current_comm();
            (*rec_ptr).creator_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
        }
        EVENT_KIND_NETWORK_FILE_OPEN
    } else if let Some(src) = PROP_PIDS.get_ptr(pid) {
        // Inherit the source file's origin. Both maps hold OriginRecord, so
        // this is a map→map copy with no by-value stack temporary.
        unsafe { core::ptr::copy_nonoverlapping(src, rec_ptr, 1) };
        EVENT_KIND_DERIVED_FILE_OPEN
    } else {
        return 0;
    };

    let path_buf = match PATH_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    let path_ptr = unsafe { &(*file_ptr).f_path } as *const KernelPath as *mut bpf_path;
    unsafe {
        // Landing path = where the file is being written right now (distinct
        // from the eventual exec-time path; the file may be renamed before
        // execve). Resolve it into the scratch buffer and hash its
        // immediate-parent folder, basename, and ancestors in one pass — so
        // bprm_check_security can match landing_folder / landing_filename
        // rules on the same-boot fast path. For the inherited (derived) case
        // this overwrites the source's landing fields so the record describes
        // *this* file's location, not the archive's. The full path string is
        // never stored — userspace logs the path → hash mapping into the
        // audit db when it sees the ringbuf event.
        let buf = (*path_buf).0.as_mut_ptr() as *mut c_char;
        let _ = bpf_d_path(path_ptr, buf, EXEC_PATH_LEN as u32);
        let (folder_hash, basename_hash) = landing_hashes(
            buf as *const u8,
            (*rec_ptr).landing_ancestor_hashes.as_mut_ptr(),
        );
        (*rec_ptr).landing_folder_hash = folder_hash;
        (*rec_ptr).landing_basename_hash = basename_hash;
    }

    // In-kernel mark: write the OriginRecord into inode storage right now.
    // bprm_check_security can then enforce on this inode without waiting on
    // userspace to land the xattr.
    if !inode_ptr.is_null() {
        let _ = unsafe { INODE_MARKS.get_or_insert_ptr(inode_ptr, rec_ptr) };
    }

    emit_event(kind, path_ptr, pid, rec_ptr, 0);
    0
}

/// security_bprm_check(struct linux_binprm *bprm, int retval).
///
/// LSM hooks see the previous LSM's verdict in `retval` (last BTF arg). If
/// somebody already said no, we preserve that — never silently re-enable an
/// exec that landlock/apparmor blocked.
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    let retval: i32 = ctx.arg(1);
    if retval != 0 {
        return retval;
    }

    let bprm_ptr: *const KernelLinuxBinprm = ctx.arg(0);
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

    // Try xattr if there's no storage record, or storage was partial
    // (file_open wrote the landing hashes but not creator_path_hash;
    // userspace fills that only in the xattr).
    let need_xattr = !have_storage || unsafe { (*buf).creator_path_hash == 0 };
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
            EXEC_PATH_LEN as u32,
        );
    }

    let mode = CONFIG.get(CONFIG_MODE).copied().unwrap_or(0);
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

/// `landing_folder` rule match: the rule's folder hash equals the
/// record's immediate-parent hash (exact, any depth) OR any stored
/// ancestor hash (nested, up to `MAX_FOLDER_ANCESTORS` levels). Fixed
/// loop, constant index — no per-element bounds concern.
#[inline(always)]
fn landing_folder_match(origin: &OriginRecord, needle: u64) -> bool {
    if needle == 0 {
        return false;
    }
    if origin.landing_folder_hash == needle {
        return true;
    }
    let mut found = false;
    for j in 0..MAX_FOLDER_ANCESTORS {
        if origin.landing_ancestor_hashes[j] == needle {
            found = true;
        }
    }
    found
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

// `bpf_loop` (helper id 181, kernel >= 5.17): runs `callback_fn` up
// to `nr_loops` times; the callback returns 0 to continue, 1 to break.
// We use it for the per-path FNV walks so the verifier inspects the
// callback once instead of unrolling the loop body across every rule
// × every dim — which is what bounded `PATH_HASH_SCAN_LEN` to 80 in
// the static-loop version.
type LoopCb = unsafe extern "C" fn(u32, *mut c_void) -> i64;

#[inline(always)]
unsafe fn bpf_loop(nr_loops: u32, cb: LoopCb, ctx: *mut c_void, flags: u64) -> i64 {
    let fun: unsafe extern "C" fn(u32, *mut c_void, *mut c_void, u64) -> i64 =
        core::mem::transmute(181usize);
    fun(nr_loops, cb as *mut c_void, ctx, flags)
}

#[repr(C)]
struct FnvCtx {
    src: *const u8,
    hash: u64,
}

/// `bpf_loop` callback for [`fnv_full`]. Marked `#[inline(never)]`
/// so the linker emits it as a real subprog — the whole point of
/// switching to `bpf_loop` is to let the verifier amortize this body
/// across iterations, which only works if it's a separate function.
///
/// The explicit `i >= PATH_HASH_SCAN_LEN` bound check teaches the
/// verifier the upper bound on the index — without it, `i` is a u32
/// the verifier treats as `[0, u32::MAX]`, which makes `src + i` an
/// unbounded memory access regardless of what `bpf_loop` actually
/// passes in.
#[inline(never)]
unsafe extern "C" fn fnv_step(i: u32, ctx: *mut c_void) -> i64 {
    if i >= PATH_HASH_SCAN_LEN as u32 {
        return 1;
    }
    let ctx = &mut *(ctx as *mut FnvCtx);
    let b = *ctx.src.add(i as usize);
    if b == 0 {
        return 1; // break
    }
    ctx.hash ^= b as u64;
    ctx.hash = ctx.hash.wrapping_mul(FNV_PRIME);
    0
}

/// FNV-1a-64 of a NUL-terminated path. Scans up to
/// [`PATH_HASH_SCAN_LEN`] bytes via `bpf_loop`.
#[inline(always)]
unsafe fn fnv_full(src: *const u8) -> u64 {
    let mut ctx = FnvCtx {
        src,
        hash: FNV_OFFSET,
    };
    bpf_loop(
        PATH_HASH_SCAN_LEN as u32,
        fnv_step,
        &mut ctx as *mut _ as *mut c_void,
        0,
    );
    ctx.hash
}

#[repr(C)]
struct FolderCtx {
    src: *const u8,
    needle: u64,
    hash: u64,
    found: u32,
}

#[inline(never)]
unsafe extern "C" fn folder_step(i: u32, ctx: *mut c_void) -> i64 {
    if i >= PATH_HASH_SCAN_LEN as u32 {
        return 1;
    }
    let ctx = &mut *(ctx as *mut FolderCtx);
    let b = *ctx.src.add(i as usize);
    if b == 0 {
        return 1; // break
    }
    ctx.hash ^= b as u64;
    ctx.hash = ctx.hash.wrapping_mul(FNV_PRIME);
    if b == b'/' && ctx.hash == ctx.needle {
        ctx.found = 1;
    }
    0
}

/// True if `needle` equals the FNV-1a hash of any `/`-terminated prefix
/// of the NUL-terminated path at `src`. Walks the path once via
/// `bpf_loop`, checking at each separator.
#[inline(always)]
unsafe fn folder_match(src: *const u8, needle: u64) -> bool {
    let mut ctx = FolderCtx {
        src,
        needle,
        hash: FNV_OFFSET,
        found: 0,
    };
    bpf_loop(
        PATH_HASH_SCAN_LEN as u32,
        folder_step,
        &mut ctx as *mut _ as *mut c_void,
        0,
    );
    ctx.found != 0
}

#[repr(C)]
struct LandingCtx {
    src: *const u8,
    /// Running FNV over the whole path so far.
    full_hash: u64,
    /// Running FNV over the current path component (reset after each `/`).
    comp_hash: u64,
    /// `full_hash` captured at the most recent `/` — the immediate parent.
    folder_hash: u64,
    /// Count of `/`-prefixes seen (drives the masked array index).
    count: u32,
    _pad: u32,
    /// FNV of each `/`-terminated prefix, shallow → deep. By-value in the
    /// ctx (not a pointer into a map value) so the bpf_loop callback
    /// writes to its own stack frame — keeps the verifier's pointer
    /// provenance simple. Copied into the record after the walk.
    ancestors: [u64; MAX_FOLDER_ANCESTORS],
}

#[inline(never)]
unsafe extern "C" fn landing_step(i: u32, ctx: *mut c_void) -> i64 {
    if i >= PATH_HASH_SCAN_LEN as u32 {
        return 1;
    }
    let ctx = &mut *(ctx as *mut LandingCtx);
    let b = *ctx.src.add(i as usize);
    if b == 0 {
        return 1; // break
    }
    ctx.full_hash ^= b as u64;
    ctx.full_hash = ctx.full_hash.wrapping_mul(FNV_PRIME);
    if b == b'/' {
        // Prefix up to & including this slash = an ancestor folder. The
        // last one seen is the immediate parent.
        ctx.folder_hash = ctx.full_hash;
        // Masked index: provably in-bounds with no panic branch (N is a
        // power of two). Real paths stay under N, so this never wraps.
        let idx = (ctx.count as usize) & (MAX_FOLDER_ANCESTORS - 1);
        ctx.ancestors[idx] = ctx.full_hash;
        ctx.count = ctx.count.wrapping_add(1);
        // The basename is whatever follows the final slash, so restart
        // the component hash from the offset basis here.
        ctx.comp_hash = FNV_OFFSET;
    } else {
        ctx.comp_hash ^= b as u64;
        ctx.comp_hash = ctx.comp_hash.wrapping_mul(FNV_PRIME);
    }
    0
}

/// One pass over a NUL-terminated path. Fills `out_ancestors` (a
/// `[u64; MAX_FOLDER_ANCESTORS]` in the record) with each `/`-terminated
/// prefix hash for nested `landing_folder` matching, and returns
/// `(folder_hash, basename_hash)`:
///   * `folder_hash` = FNV of the immediate parent directory **including
///     its trailing `/`** (matches userspace `normalize_folder`), for
///     exact matching and soak/log resolution.
///   * `basename_hash` = FNV of the final path component (no slash).
///
/// Not inlined: the by-value `ancestors` array makes this a ~290-byte
/// frame, kept off `file_open`'s stack.
#[inline(never)]
unsafe fn landing_hashes(src: *const u8, out_ancestors: *mut u64) -> (u64, u64) {
    let mut ctx = LandingCtx {
        src,
        full_hash: FNV_OFFSET,
        comp_hash: FNV_OFFSET,
        folder_hash: 0,
        count: 0,
        _pad: 0,
        ancestors: [0u64; MAX_FOLDER_ANCESTORS],
    };
    bpf_loop(
        PATH_HASH_SCAN_LEN as u32,
        landing_step,
        &mut ctx as *mut _ as *mut c_void,
        0,
    );
    core::ptr::copy_nonoverlapping(ctx.ancestors.as_ptr(), out_ancestors, MAX_FOLDER_ANCESTORS);
    (ctx.folder_hash, ctx.comp_hash)
}

#[repr(C)]
struct ParentCtx {
    src: *const u8,
    full_hash: u64,
    folder_hash: u64,
}

#[inline(never)]
unsafe extern "C" fn parent_step(i: u32, ctx: *mut c_void) -> i64 {
    if i >= PATH_HASH_SCAN_LEN as u32 {
        return 1;
    }
    let ctx = &mut *(ctx as *mut ParentCtx);
    let b = *ctx.src.add(i as usize);
    if b == 0 {
        return 1;
    }
    ctx.full_hash ^= b as u64;
    ctx.full_hash = ctx.full_hash.wrapping_mul(FNV_PRIME);
    if b == b'/' {
        ctx.folder_hash = ctx.full_hash;
    }
    0
}

/// FNV of a NUL-terminated path's immediate parent directory (the prefix
/// up to and including the last `/`). Used for **exact** `target_folder`
/// matching of the live exec path.
#[inline(always)]
unsafe fn parent_folder_hash(src: *const u8) -> u64 {
    let mut ctx = ParentCtx {
        src,
        full_hash: FNV_OFFSET,
        folder_hash: 0,
    };
    bpf_loop(
        PATH_HASH_SCAN_LEN as u32,
        parent_step,
        &mut ctx as *mut _ as *mut c_void,
        0,
    );
    ctx.folder_hash
}

/// Returns true if any allowlist rule's conditions all match. Rules OR
/// together; within a rule, dim conditions AND.
///
/// Folder dims are exact by default and recursive when the rule carries
/// the matching `*_FOLDER_RECURSIVE` modifier (`/opt/app/` vs
/// `/opt/app/*`):
///   * **target_folder** — exact compares the live exec path's immediate
///     parent; recursive matches any `/`-prefix of it (walk, any depth
///     to `PATH_MAX`). **target_filename** matches the full live path.
///   * **landing_folder** — exact compares the stored immediate-parent
///     hash; recursive matches any stored ancestor hash (up to
///     `MAX_FOLDER_ANCESTORS` levels). **landing_filename** matches the
///     basename; **creator_process** the exe path. All hash compares.
#[inline(always)]
unsafe fn check_allowlist(filename: &[u8; EXEC_PATH_LEN], origin: &OriginRecord) -> bool {
    let count = ALLOW_RULE_COUNT.get(0).copied().unwrap_or(0);
    if count == 0 {
        return false;
    }
    let exec_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    // Immediate parent of the live exec path, for exact target_folder
    // rules. Computed once (one walk); recursive rules still walk per
    // rule via folder_match.
    let target_parent = parent_folder_hash(filename.as_ptr());

    let n = if count as usize > MAX_RULES {
        MAX_RULES as u32
    } else {
        count
    };
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
        // creator_process: direct hash compare. 0 means "not yet
        // augmented" (file_open didn't know the creator exe) — treat as
        // no-match so we never permit on a half-filled record.
        if (f & dim::CREATOR_PROCESS) != 0
            && (origin.creator_path_hash == 0
                || origin.creator_path_hash != rule.creator_process_hash)
        {
            continue;
        }
        // landing dims: direct hash compares against the stored record.
        if (f & dim::LANDING_FILENAME) != 0
            && origin.landing_basename_hash != rule.landing_filename_hash
        {
            continue;
        }
        if (f & dim::LANDING_FOLDER) != 0 {
            let ok = if (f & dim::LANDING_FOLDER_RECURSIVE) != 0 {
                // recursive: immediate parent or any stored ancestor.
                landing_folder_match(origin, rule.landing_folder_hash)
            } else {
                // exact: the immediate parent only.
                rule.landing_folder_hash != 0
                    && origin.landing_folder_hash == rule.landing_folder_hash
            };
            if !ok {
                continue;
            }
        }
        // target dims: against the live exec path.
        if (f & dim::TARGET_FILENAME) != 0
            && fnv_full(filename.as_ptr()) != rule.target_filename_hash
        {
            continue;
        }
        if (f & dim::TARGET_FOLDER) != 0 {
            let ok = if (f & dim::TARGET_FOLDER_RECURSIVE) != 0 {
                // recursive: rule folder is any `/`-prefix of the path.
                folder_match(filename.as_ptr(), rule.target_folder_hash)
            } else {
                // exact: rule folder is the file's immediate parent.
                rule.target_folder_hash != 0 && target_parent == rule.target_folder_hash
            };
            if !ok {
                continue;
            }
        }
        return true;
    }
    false
}

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
            EXEC_PATH_LEN as u32,
        );
    }
    entry.submit(0);
}

#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid = current_pid();
    let _ = NET_PIDS.remove(pid);
    let _ = PROP_PIDS.remove(pid);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

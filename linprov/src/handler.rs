//! Ring-buffer event handler.
//!
//! Phase B: the eBPF programs do both the xattr write (via
//! `bpf_set_dentry_xattr`) and the xattr check (via `bpf_get_file_xattr`)
//! in-kernel. Userspace just logs what the kernel reports.

use std::path::PathBuf;

use linprov_common::{
    Event, OriginRecord, EVENT_KIND_EXECVE, EVENT_KIND_NETWORK_FILE_OPEN, PATH_LEN, XATTR_NAME,
};
use log::{debug, info, warn};

pub struct Config;

pub fn handle_event(_cfg: &Config, raw: &[u8]) {
    if raw.len() < std::mem::size_of::<Event>() {
        warn!(
            "short ring-buf record: got {} bytes, expected {}",
            raw.len(),
            std::mem::size_of::<Event>()
        );
        return;
    }
    let event: &Event =
        match bytemuck::try_from_bytes::<Event>(&raw[..std::mem::size_of::<Event>()]) {
            Ok(e) => e,
            Err(e) => {
                warn!("failed to cast ring-buf record to Event: {e}");
                return;
            }
        };

    match event.kind {
        EVENT_KIND_NETWORK_FILE_OPEN => on_file_marked(event),
        EVENT_KIND_EXECVE => on_execve_marked(event),
        other => warn!("unknown event kind: {other}"),
    }
}

fn on_file_marked(event: &Event) {
    let path = c_str_to_string(&event.filename);
    let comm = comm_to_string(&event.comm);
    let target = PathBuf::from(&path);

    // Filter out non-regular targets — bpf_d_path can resolve pseudo-fs
    // entries that we don't want to mark.
    if is_pseudo_fs(&target) {
        debug!("skipping non-regular target: {}", target.display());
        return;
    }

    // Mirror the eBPF record bytes verbatim. Userspace still does the write
    // until we resolve the trusted-dentry issue for bpf_set_dentry_xattr.
    let value = bytemuck::bytes_of(&event.origin).to_vec();

    match xattr::set(&target, XATTR_NAME, &value) {
        Ok(()) => info!(
            "marked {} (pid={} comm={} ts_boot_ns={})",
            target.display(),
            event.pid,
            comm,
            event.origin.ts_boot_ns
        ),
        Err(e) => debug!(
            "setxattr({}, {XATTR_NAME}) failed: {e}",
            target.display()
        ),
    }
}

fn is_pseudo_fs(target: &std::path::Path) -> bool {
    let Some(s) = target.to_str() else { return true };
    s.starts_with("/dev/")
        || s.starts_with("/proc/")
        || s.starts_with("/sys/")
        || s.starts_with("/run/")
}

fn on_execve_marked(event: &Event) {
    let path = c_str_to_string(&event.filename);
    let comm = comm_to_string(&event.comm);
    info!(
        "PROVENANCE-EXEC path={} pid={} comm={} origin={}",
        path,
        event.pid,
        comm,
        format_origin(&event.origin),
    );
}

fn format_origin(o: &OriginRecord) -> String {
    let comm = comm_to_string(&o.comm);
    format!(
        "{{v:{},ts_boot_ns:{},pid:{},comm:{}}}",
        o.version, o.ts_boot_ns, o.pid, comm
    )
}

fn comm_to_string(comm: &[u8; linprov_common::COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn c_str_to_string(buf: &[u8; PATH_LEN]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

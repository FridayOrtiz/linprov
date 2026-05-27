//! Ring-buffer event handler.
//!
//! In all modes the eBPF program does the xattr READ in-kernel via
//! `bpf_get_file_xattr`; userspace handles the xattr WRITE side and, in
//! soak/enforce modes, the allowlist plumbing.

use std::{
    collections::HashSet,
    fs::File,
    path::PathBuf,
    sync::Mutex,
};

use linprov_common::{
    Event, OriginRecord, EVENT_KIND_EXECVE, EVENT_KIND_NETWORK_FILE_OPEN, PATH_LEN, XATTR_NAME,
};
use log::{debug, info, warn};

use crate::{append_allowlist, ModeArg};

pub struct Config {
    pub mode: ModeArg,
    /// Paths we've already seen this session (also reflects what was loaded
    /// from the allowlist file at startup). Used to dedupe soak-mode writes.
    pub seen: Mutex<HashSet<String>>,
    /// Append handle for the allowlist file, only Some in soak mode.
    pub allowlist_writer: Option<Mutex<File>>,
}

pub fn handle_event(cfg: &Config, raw: &[u8]) {
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
        EVENT_KIND_EXECVE => on_execve_marked(cfg, event),
        other => warn!("unknown event kind: {other}"),
    }
}

fn on_file_marked(event: &Event) {
    let path = c_str_to_string(&event.filename);
    let comm = comm_to_string(&event.comm);
    let target = PathBuf::from(&path);

    if is_pseudo_fs(&target) {
        debug!("skipping non-regular target: {}", target.display());
        return;
    }

    // Mirror the eBPF record bytes verbatim. The eBPF side already serialized
    // the OriginRecord; we just write it as the xattr value.
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

fn on_execve_marked(cfg: &Config, event: &Event) {
    let path = c_str_to_string(&event.filename);
    let comm = comm_to_string(&event.comm);

    if event.status != 0 {
        warn!(
            "BLOCKED-EXEC path={} pid={} comm={} origin={} (LSM verdict {})",
            path,
            event.pid,
            comm,
            format_origin(&event.origin),
            event.status,
        );
        return;
    }

    info!(
        "PROVENANCE-EXEC path={} pid={} comm={} origin={}",
        path,
        event.pid,
        comm,
        format_origin(&event.origin),
    );

    if cfg.mode == ModeArg::Soak {
        soak_record(cfg, &path);
    }
}

fn soak_record(cfg: &Config, path: &str) {
    let mut seen = cfg.seen.lock().expect("seen mutex poisoned");
    if !seen.insert(path.to_string()) {
        return;
    }
    let Some(writer) = cfg.allowlist_writer.as_ref() else { return };
    if let Err(e) = append_allowlist(writer, path) {
        warn!("failed to append `{path}` to allowlist: {e}");
    } else {
        info!("soak: added `{path}` to allowlist");
    }
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

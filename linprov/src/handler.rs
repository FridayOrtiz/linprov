//! Ring-buffer event handler.
//!
//! The eBPF side fills `filename` via bpf_d_path() for every event we get
//! here, so paths are already absolute and pinned to the file the kernel
//! was acting on. No /proc/<pid>/cwd resolution needed.
//!
//! Two event kinds:
//!   1. NetworkFileOpen: a network-flagged process opened a file for writing.
//!      Apply the provenance xattr.
//!   2. Execve: bprm_check_security fired. Read the xattr off the target
//!      binary and log it if the mark is present.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use linprov_common::{
    Event, EVENT_KIND_EXECVE, EVENT_KIND_NETWORK_FILE_OPEN, PATH_LEN, XATTR_NAME,
};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

pub struct Config {
    pub dry_run: bool,
}

/// Schema of the xattr value. Versioned so we can evolve the format later
/// (e.g. add remote address, URL, hash) without breaking existing files.
#[derive(Debug, Serialize, Deserialize)]
struct OriginRecord {
    v: u32,
    source: String,
    ts: u64,
    pid: u32,
    comm: String,
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
        EVENT_KIND_NETWORK_FILE_OPEN => on_network_file_open(cfg, event),
        EVENT_KIND_EXECVE => on_execve(event),
        other => warn!("unknown event kind: {other}"),
    }
}

fn on_network_file_open(cfg: &Config, event: &Event) {
    let filename = match c_str_to_string(&event.filename) {
        Some(s) if !s.is_empty() => s,
        _ => {
            debug!("network-open event with empty filename (pid={})", event.pid);
            return;
        }
    };
    let target = PathBuf::from(&filename);

    if !is_regular_target(&target) {
        debug!("skipping non-regular target: {}", target.display());
        return;
    }

    let comm = comm_to_string(&event.comm);
    let record = OriginRecord {
        v: 1,
        source: "network".to_string(),
        ts: now_secs(),
        pid: event.pid,
        comm: comm.clone(),
    };
    let value = match serde_json::to_vec(&record) {
        Ok(v) => v,
        Err(e) => {
            warn!("failed to serialize origin record: {e}");
            return;
        }
    };

    if cfg.dry_run {
        info!(
            "[dry-run] would mark {} (pid={} comm={})",
            target.display(),
            event.pid,
            comm
        );
        return;
    }

    match xattr::set(&target, XATTR_NAME, &value) {
        Ok(()) => info!(
            "marked {} (pid={} comm={})",
            target.display(),
            event.pid,
            comm
        ),
        Err(e) => {
            debug!(
                "setxattr({}, {XATTR_NAME}) failed: {e}",
                target.display()
            );
        }
    }
}

fn on_execve(event: &Event) {
    let filename = match c_str_to_string(&event.filename) {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };
    let path = PathBuf::from(&filename);

    match xattr::get(&path, XATTR_NAME) {
        Ok(Some(value)) => {
            let comm = comm_to_string(&event.comm);
            let origin = std::str::from_utf8(&value)
                .unwrap_or("<non-utf8>")
                .to_string();
            info!(
                "PROVENANCE-EXEC path={} pid={} comm={} origin={}",
                path.display(),
                event.pid,
                comm,
                origin
            );
        }
        Ok(None) => {
            debug!("execve unmarked: {}", path.display());
        }
        Err(e) => {
            debug!("getxattr({}) failed: {e}", path.display());
        }
    }
}

fn is_regular_target(target: &Path) -> bool {
    let Some(s) = target.to_str() else { return false };
    if s.starts_with("/dev/")
        || s.starts_with("/proc/")
        || s.starts_with("/sys/")
        || s.starts_with("/run/")
    {
        return false;
    }
    true
}

fn comm_to_string(comm: &[u8; linprov_common::COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn c_str_to_string(buf: &[u8; PATH_LEN]) -> Option<String> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

//! Ring-buffer event handler.
//!
//! `NetworkFileOpen` events: read `/proc/$pid/exe` to fill the creator's
//! full exe path, then write the augmented `OriginRecord` to the
//! `security.bpf.linprov.origin` xattr.
//!
//! `Execve` events (only emitted when the file was marked): log; in
//! enforce mode the LSM verdict in `event.status` tells us whether the
//! exec was blocked; in soak mode we emit one allowlist rule per
//! configured dimension.

use std::{fs, path::PathBuf};

use linprov_common::{
    Event, OriginRecord, COMM_LEN, CREATOR_PATH_LEN, EVENT_KIND_EXECVE,
    EVENT_KIND_NETWORK_FILE_OPEN, ORIGIN_VERSION, PATH_LEN, XATTR_NAME,
};
use log::{debug, info, warn};

use crate::{
    allowlist::{OriginContext, Soak},
    ModeArg,
};

pub struct Config {
    pub mode: ModeArg,
    pub soak: Option<Soak>,
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

    // Augment the OriginRecord with the creator's full exe path. /proc/$pid/exe
    // is a symlink to the binary the process was exec'd from. Best-effort:
    // if the creator already exited we keep creator_path empty, and rules
    // keyed on it just won't match.
    let mut augmented: OriginRecord = event.origin;
    augmented.version = ORIGIN_VERSION;
    let creator_path = read_creator_exe(event.pid);
    if let Some(p) = creator_path.as_deref() {
        write_path_field(&mut augmented.creator_path, p);
    }

    let value = bytemuck::bytes_of(&augmented).to_vec();

    match xattr::set(&target, XATTR_NAME, &value) {
        Ok(()) => info!(
            "marked {} (pid={} comm={} uid={} creator_path={} ts_boot_ns={})",
            target.display(),
            event.pid,
            comm,
            augmented.creator_uid,
            creator_path.as_deref().unwrap_or("<unknown>"),
            event.origin.ts_boot_ns
        ),
        Err(e) => debug!("setxattr({}, {XATTR_NAME}) failed: {e}", target.display()),
    }
}

fn read_creator_exe(pid: u32) -> Option<String> {
    let link = format!("/proc/{pid}/exe");
    match fs::read_link(&link) {
        Ok(p) => Some(p.to_string_lossy().into_owned()),
        Err(e) => {
            debug!("read_link({link}) failed: {e}");
            None
        }
    }
}

fn write_path_field(buf: &mut [u8; CREATOR_PATH_LEN], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(CREATOR_PATH_LEN - 1);
    buf[..n].copy_from_slice(&bytes[..n]);
}

fn is_pseudo_fs(target: &std::path::Path) -> bool {
    let Some(s) = target.to_str() else {
        return true;
    };
    s.starts_with("/dev/")
        || s.starts_with("/proc/")
        || s.starts_with("/sys/")
        || s.starts_with("/run/")
}

fn on_execve_marked(cfg: &Config, event: &Event) {
    let target_path = c_str_to_string(&event.filename);
    let landing_path = c_str_to_string(&event.origin.landing_filename);
    let exec_comm = comm_to_string(&event.comm);
    let creator_comm = comm_to_string(&event.origin.comm);
    let creator_path = c_str_to_string_full(&event.origin.creator_path);

    if event.status != 0 {
        warn!(
            "BLOCKED-EXEC target={} landing={} pid={} comm={} origin={} (LSM verdict {})",
            target_path,
            landing_path,
            event.pid,
            exec_comm,
            format_origin(&event.origin, &creator_comm, &creator_path),
            event.status,
        );
        return;
    }

    info!(
        "PROVENANCE-EXEC target={} landing={} pid={} comm={} origin={}",
        target_path,
        landing_path,
        event.pid,
        exec_comm,
        format_origin(&event.origin, &creator_comm, &creator_path),
    );

    if cfg.mode == ModeArg::Soak {
        if let Some(soak) = cfg.soak.as_ref() {
            let exec_uid = get_uid_for_pid(event.pid).unwrap_or(0);
            let ctx = OriginContext {
                target_filename: &target_path,
                landing_filename: &landing_path,
                creator_path: &creator_path,
                creator_comm: &creator_comm,
                creator_uid: event.origin.creator_uid,
                execution_uid: exec_uid,
            };
            match soak.record(&ctx) {
                Ok(Some(line)) => info!("soak: added `{line}`"),
                Ok(None) => {}
                Err(e) => warn!("soak append failed: {e}"),
            }
        }
    }
}

fn get_uid_for_pid(pid: u32) -> Option<u32> {
    let s = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Uid: <real> <effective> <saved> <fs>
            let real = rest.split_whitespace().next()?;
            return real.parse().ok();
        }
    }
    None
}

fn format_origin(o: &OriginRecord, creator_comm: &str, creator_path: &str) -> String {
    format!(
        "{{v:{},ts_boot_ns:{},pid:{},uid:{},comm:{},path:{}}}",
        o.version,
        o.ts_boot_ns,
        o.pid,
        o.creator_uid,
        creator_comm,
        if creator_path.is_empty() {
            "<unknown>"
        } else {
            creator_path
        }
    )
}

fn comm_to_string(comm: &[u8; COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn c_str_to_string(buf: &[u8; PATH_LEN]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn c_str_to_string_full(buf: &[u8; CREATOR_PATH_LEN]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

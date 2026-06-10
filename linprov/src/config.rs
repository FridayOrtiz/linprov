//! `/etc/linprov/config.toml` parsing and config-vs-CLI merging.
//!
//! Resolution order, highest priority wins:
//!   1. CLI flag explicitly given on the command line
//!   2. Env var (e.g. `LINPROV_MARK_LOCALHOST`)
//!   3. Value from the TOML config file
//!   4. Built-in default
//!
//! Clap can't distinguish "user said `--mode observe`" from "default
//! value is observe", so each CLI arg is an `Option<T>`; merging walks
//! through `cli.or(file).unwrap_or(default)`.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Deserialize;

use crate::{allowlist::Dim, mode::Mode};

/// Whether the daemon exposes its control socket to a local desktop agent.
/// `Off` (default) keeps the socket root-only (0600) — headless behavior.
/// `Tray` chmods it 0660 group `linprov` so a user-session `linprov notify`
/// tray agent can subscribe to blocks and issue allows.
#[derive(Clone, Copy, Debug, Default, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NotifyMode {
    #[default]
    Off,
    Tray,
}

/// Default location the daemon reads at startup if `--config` isn't
/// passed. `setup` writes here.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/linprov/config.toml";

/// Default allowlist path, used both by `setup` (what it writes) and
/// by `run` if neither the CLI nor the config file specifies one.
pub const DEFAULT_ALLOWLIST_PATH: &str = "/etc/linprov/list.allow";

/// Default systemd unit path that `setup` writes and `upgrade` acts on.
pub const DEFAULT_SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/linprov.service";

/// Default name of the systemd unit (without the file extension).
pub const DEFAULT_SYSTEMD_UNIT_NAME: &str = "linprov.service";

/// Root-only unix control socket the daemon listens on and `linprov allow`
/// connects to. Lives in `/run` (tmpfs) so it's recreated each boot; the
/// daemon manages it (creates the dir, removes a stale socket on bind, and
/// unlinks on shutdown). `setup` adds `RuntimeDirectory=linprov` so systemd
/// owns the directory's lifecycle.
pub const DEFAULT_CONTROL_SOCKET_PATH: &str = "/run/linprov/control.sock";

/// Default plaintext hash → path audit db. Maps every FNV hash the
/// daemon stores in a record back to its path, for log resolution,
/// soak rule emission, and `grep`-based auditing. `/var/lib` is the
/// conventional home for app state that should persist across reboots.
pub const DEFAULT_HASHDB_PATH: &str = "/var/lib/linprov/hashes.tsv";

/// Where `setup` and `upgrade` copy the binary so it lands on root's
/// `secure_path` (and `sudo linprov ...` works without a leading
/// absolute path). `/usr/local/bin` is the conventional spot for
/// admin-installed binaries that aren't managed by the distro package
/// manager.
pub const DEFAULT_INSTALL_PATH: &str = "/usr/local/bin/linprov";

/// Shape of the on-disk TOML config. All fields are optional so users
/// can opt into things piecewise.
#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
    pub mode: Option<Mode>,
    pub allowlist: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub log_level: Option<String>,
    pub mark_localhost: Option<bool>,
    pub soak: Option<Vec<Dim>>,
    pub hash_db: Option<PathBuf>,
    /// Expose the control socket to a local desktop agent — see
    /// [`NotifyMode`]. Defaults to `off`.
    pub notifications: Option<NotifyMode>,
    /// Script interpreters (by `comm`) whose reads of a marked file are
    /// enforced like an execve — see [`default_interpreters`]. An explicit
    /// empty list (`interpreters = []`) disables script enforcement.
    pub interpreters: Option<Vec<String>>,
}

/// Built-in interpreter `comm` set used when neither the CLI nor the
/// config file specifies one. These are the common shells / language
/// runtimes that load a script by reading it (so the script never reaches
/// the execve hook). Matched against the reader's `comm`, which the kernel
/// truncates to 15 bytes — names here stay well under that.
pub fn default_interpreters() -> Vec<String> {
    [
        "sh", "bash", "dash", "zsh", "ash", "ksh", "fish", "python", "python3", "perl", "ruby",
        "node", "php", "lua", "awk", "gawk", "tclsh",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl FileConfig {
    /// Read the file at `path`, parse, and return. A missing file is
    /// returned as the default empty config; any other error is fatal.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s)
                .with_context(|| format!("parsing config file `{}`", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading `{}`", path.display())),
        }
    }
}

/// Final resolved values after CLI > env > file > built-in defaults.
#[derive(Debug)]
pub struct EffectiveConfig {
    pub mode: Mode,
    pub allowlist: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub log_level: String,
    pub mark_localhost: bool,
    pub soak: Vec<Dim>,
    pub hash_db: PathBuf,
    pub interpreters: Vec<String>,
    pub notifications: NotifyMode,
}

impl EffectiveConfig {
    /// `cli` carries `Option<T>` for each user-overridable field; `file`
    /// is the on-disk TOML config (or default if no file present).
    pub fn resolve(cli: CliOverrides, file: FileConfig) -> Self {
        Self {
            mode: cli.mode.or(file.mode).unwrap_or(Mode::Observe),
            allowlist: cli.allowlist.or(file.allowlist),
            log_file: cli.log_file.or(file.log_file),
            log_level: cli
                .log_level
                .or(file.log_level)
                .unwrap_or_else(|| "info".to_string()),
            mark_localhost: cli.mark_localhost.or(file.mark_localhost).unwrap_or(false),
            soak: cli
                .soak
                .or(file.soak)
                .unwrap_or_else(|| vec![Dim::CreatorProcess]),
            hash_db: cli
                .hash_db
                .or(file.hash_db)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_HASHDB_PATH)),
            interpreters: cli
                .interpreters
                .or(file.interpreters)
                .unwrap_or_else(default_interpreters),
            notifications: cli
                .notifications
                .or(file.notifications)
                .unwrap_or_default(),
        }
    }
}

/// The subset of `RunArgs` that participates in config-file merging.
/// Built by `run::execute` from the parsed CLI struct.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub mode: Option<Mode>,
    pub allowlist: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub log_level: Option<String>,
    pub mark_localhost: Option<bool>,
    pub soak: Option<Vec<Dim>>,
    pub hash_db: Option<PathBuf>,
    pub interpreters: Option<Vec<String>>,
    pub notifications: Option<NotifyMode>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_yields_defaults() {
        let eff = EffectiveConfig::resolve(CliOverrides::default(), FileConfig::default());
        assert_eq!(eff.mode, Mode::Observe);
        assert_eq!(eff.log_level, "info");
        assert!(!eff.mark_localhost);
        assert_eq!(eff.soak, vec![Dim::CreatorProcess]);
        assert!(eff.allowlist.is_none());
        assert!(eff.log_file.is_none());
        // Interpreters default to the built-in set, and an explicit empty
        // list (disable) round-trips through resolution.
        assert!(eff.interpreters.contains(&"bash".to_string()));
        let disabled = EffectiveConfig::resolve(
            CliOverrides {
                interpreters: Some(vec![]),
                ..Default::default()
            },
            FileConfig::default(),
        );
        assert!(disabled.interpreters.is_empty());
    }

    #[test]
    fn cli_beats_file() {
        let cli = CliOverrides {
            mode: Some(Mode::Enforce),
            allowlist: Some(PathBuf::from("/cli/allow")),
            ..Default::default()
        };
        let file = FileConfig {
            mode: Some(Mode::Observe),
            allowlist: Some(PathBuf::from("/file/allow")),
            log_level: Some("debug".to_string()),
            ..Default::default()
        };
        let eff = EffectiveConfig::resolve(cli, file);
        assert_eq!(eff.mode, Mode::Enforce);
        assert_eq!(eff.allowlist, Some(PathBuf::from("/cli/allow")));
        assert_eq!(eff.log_level, "debug"); // file value used; not on CLI
    }

    #[test]
    fn file_round_trip() {
        let toml_src = r#"
            mode = "enforce"
            allowlist = "/etc/linprov/list.allow"
            log_file = "/var/log/linprov.log"
            log_level = "warn"
            mark_localhost = true
            soak = ["creator_process", "creator_uid"]
        "#;
        let file: FileConfig = toml::from_str(toml_src).unwrap();
        let eff = EffectiveConfig::resolve(CliOverrides::default(), file);
        assert_eq!(eff.mode, Mode::Enforce);
        assert_eq!(
            eff.allowlist,
            Some(PathBuf::from("/etc/linprov/list.allow"))
        );
        assert_eq!(eff.log_file, Some(PathBuf::from("/var/log/linprov.log")));
        assert_eq!(eff.log_level, "warn");
        assert!(eff.mark_localhost);
        assert_eq!(eff.soak, vec![Dim::CreatorProcess, Dim::CreatorUid]);
    }

    #[test]
    fn load_missing_file_is_default() {
        let p = PathBuf::from("/nonexistent/linprov-config.toml");
        let f = FileConfig::load_or_default(&p).unwrap();
        assert!(f.mode.is_none());
        assert!(f.allowlist.is_none());
    }
}

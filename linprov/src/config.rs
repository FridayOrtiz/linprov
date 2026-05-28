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
use serde::Deserialize;

use crate::{allowlist::Dim, mode::Mode};

/// Default location the daemon reads at startup if `--config` isn't
/// passed. `setup` writes here.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/linprov/config.toml";

/// Default allowlist path, used both by `setup` (what it writes) and
/// by `run` if neither the CLI nor the config file specifies one.
pub const DEFAULT_ALLOWLIST_PATH: &str = "/etc/linprov/list.allow";

/// Default log file path. `setup` writes this into the generated
/// config; `run` falls back to stderr if the field is absent.
pub const DEFAULT_LOG_PATH: &str = "/var/log/linprov.log";

/// Default systemd unit path that `setup` writes and `upgrade` acts on.
pub const DEFAULT_SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/linprov.service";

/// Default name of the systemd unit (without the file extension).
pub const DEFAULT_SYSTEMD_UNIT_NAME: &str = "linprov.service";

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

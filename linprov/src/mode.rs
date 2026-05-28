//! The operating mode enum, shared between CLI parsing, the TOML config
//! file, and the daemon entry. Lives in its own module so both clap's
//! `ValueEnum` and serde's `Deserialize` can derive on it without
//! pulling in the rest of `main.rs`.

use clap::ValueEnum;
use linprov_common::{MODE_ENFORCE, MODE_OBSERVE, MODE_SOAK};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Log only; nothing enforced or recorded persistently.
    Observe,
    /// Log and append one rule per PROVENANCE-EXEC, joining all
    /// `--soak` dims into a single conjunction.
    Soak,
    /// Block execve of marked files whose origin doesn't match any
    /// allowlist rule. `-EPERM` from `security_bprm_check`.
    Enforce,
}

impl Mode {
    pub fn as_u32(self) -> u32 {
        match self {
            Mode::Observe => MODE_OBSERVE,
            Mode::Soak => MODE_SOAK,
            Mode::Enforce => MODE_ENFORCE,
        }
    }
}

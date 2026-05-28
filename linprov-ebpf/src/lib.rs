//! Trivial source-locator shim.
//!
//! This crate exists so that `linprov` can declare us as a
//! `[build-dependencies]` entry and have cargo ship our source tree
//! into the registry cache on `cargo install linprov`. The lib has no
//! runtime logic; it just exposes the crate's manifest directory as a
//! `const` so `linprov`'s build.rs can find `src/main.rs` (the actual
//! BPF program) and drive a nested `cargo build --target
//! bpfel-unknown-none` against it.
//!
//! `no_std` because the same lib must compile for both the host (when
//! we're a build-dep of linprov) and for `bpfel-unknown-none` (when
//! we're being compiled alongside the bin via the nested build).
#![no_std]

/// Filesystem path to this crate's `Cargo.toml` parent directory, as it
/// existed when the crate was compiled.
pub const SOURCE_DIR: &str = env!("CARGO_MANIFEST_DIR");

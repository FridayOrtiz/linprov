//! Build the nested eBPF crate, then embed the resulting object into
//! the daemon binary.
//!
//! The eBPF source lives at `linprov/ebpf/`, in the daemon crate's own
//! directory rather than as a sibling workspace member, so the
//! published `linprov` tarball is self-contained (`cargo install
//! linprov` works without needing the wider workspace).
//!
//! We invoke a nested `cargo build` for the `bpfel-unknown-none` target
//! with `-Z build-std=core`, then copy the result into `OUT_DIR` so the
//! daemon's `include_bytes_aligned!` can pick it up.

use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ebpf_dir = manifest_dir.join("ebpf");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join(".cargo/config.toml").display()
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.join("ebpf-target");
    let target = "bpfel-unknown-none";
    let release = matches!(env::var("PROFILE").as_deref(), Ok("release"));

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let mut cmd = Command::new(&cargo);
    cmd.current_dir(&ebpf_dir)
        .arg("build")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target")
        .arg(target)
        .arg("--target-dir")
        .arg(&target_dir)
        // Detach inherited build-time state that would confuse the
        // nested cargo (separate lockfile, separate target dir).
        // RUSTUP_TOOLCHAIN is intentionally NOT cleared: removing it
        // makes rustup re-derive a toolchain, which on CI runners ends
        // up picking stable when the BPF crate needs nightly. Let the
        // outer toolchain propagate.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTFLAGS");

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .expect("failed to invoke nested cargo for eBPF build");
    if !status.success() {
        panic!(
            "eBPF build of linprov-ebpf failed (status: {:?})",
            status.code()
        );
    }

    let profile_dir = if release { "release" } else { "debug" };
    let src = target_dir
        .join(target)
        .join(profile_dir)
        .join("linprov-ebpf");
    let dst = out_dir.join("linprov-ebpf");
    std::fs::copy(&src, &dst).unwrap_or_else(|e| {
        panic!(
            "failed to copy eBPF object {} -> {}: {e}",
            src.display(),
            dst.display()
        )
    });
}

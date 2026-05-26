//! Build the eBPF crate before compiling the userspace binary.
//!
//! We invoke a nested `cargo build` against `linprov-ebpf` with the BPF target
//! and `-Z build-std=core`, then copy the resulting ELF object into our
//! `OUT_DIR` so the main binary can embed it via `include_bytes_aligned!`.
//!
//! The build is intentionally isolated: a separate `--target-dir`, and a
//! purge of inherited cargo/rustc env vars so the child cargo invocation
//! doesn't try to share lockfiles or rustflags with the parent build.

use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_dir = manifest_dir.parent().expect("workspace root");
    let ebpf_dir = workspace_dir.join("linprov-ebpf");
    let common_dir = workspace_dir.join("linprov-common");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("Cargo.toml").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join(".cargo/config.toml").display()
    );
    println!("cargo:rerun-if-changed={}", common_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        common_dir.join("Cargo.toml").display()
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
        // Detach from the parent cargo invocation as much as possible.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTUP_TOOLCHAIN");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().expect("failed to invoke nested cargo for eBPF build");
    if !status.success() {
        panic!("eBPF build of linprov-ebpf failed (status: {:?})", status.code());
    }

    let profile_dir = if release { "release" } else { "debug" };
    let src = target_dir.join(target).join(profile_dir).join("linprov-ebpf");
    let dst = out_dir.join("linprov-ebpf");
    std::fs::copy(&src, &dst).unwrap_or_else(|e| {
        panic!(
            "failed to copy eBPF object {} -> {}: {e}",
            src.display(),
            dst.display()
        )
    });
}

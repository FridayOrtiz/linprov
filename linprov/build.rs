//! Build the linprov-ebpf BPF object and embed it into the daemon.
//!
//! linprov-ebpf is a normal crates.io dependency (a `[build-dependencies]`
//! entry on `linprov`). On `cargo install linprov`, cargo downloads
//! linprov-ebpf into the registry cache; the lib exposes `SOURCE_DIR`
//! (`= env!("CARGO_MANIFEST_DIR")`) so we can locate its on-disk source
//! tree, then run a nested `cargo build --target bpfel-unknown-none
//! -Z build-std=core --features bpf-build` against it. The resulting
//! ELF object is copied into `OUT_DIR` so `linprov`'s main binary can
//! embed it via `include_bytes_aligned!`.

use std::{env, path::PathBuf, process::Command};

fn main() {
    let ebpf_dir = PathBuf::from(linprov_ebpf::SOURCE_DIR);

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
        .arg("--features")
        .arg("bpf-build")
        .arg("--bin")
        .arg("linprov-ebpf")
        // `--btf` is the only bpf-linker flag we need (`.BTF` section
        // for the storage maps). We deliberately DON'T pass
        // `--ignore-inline-never` any more — we want subprograms to
        // stay subprograms so the verifier can amortize per-callsite
        // state and we can use `bpf_loop()` with subprog callbacks.
        // The aya fork's `func_info` pruning patch handles the
        // compiler-emitted memset/memcpy case that originally forced
        // us to use that flag.
        //
        // The `-C` flags replicate the workspace's
        // `[profile.release.package.linprov-ebpf]` — cargo ignores
        // per-package profile blocks for workspace members AND the
        // workspace profile doesn't apply when linprov-ebpf is built
        // standalone (which is what happens under `cargo install
        // linprov`), so we set the load-bearing bits here:
        // `debuginfo=2` is required for the LLVM-BPF backend to emit
        // `.BTF`, `panic=abort` because BPF has no unwinder,
        // `overflow-checks=off` because the panic landing pads from
        // overflow checks would also need an unwinder.
        // `opt-level=3` is load-bearing, not just for speed: the BPF
        // LLVM backend can't lower several constructs without
        // optimization (e.g. aggregate/tuple returns get an "aggregate
        // returns are not supported" error at opt-level=0). The
        // workspace `[profile]` sets opt-level=3, but that doesn't apply
        // when linprov-ebpf is built standalone from the registry —
        // which is exactly what `cargo publish`'s verify step and
        // `cargo install linprov` do — so we pin it here.
        .env(
            "CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS",
            "-C link-arg=--btf \
             -C opt-level=3 -C debuginfo=2 -C panic=abort -C overflow-checks=off",
        )
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

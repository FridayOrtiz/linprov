//! Compiles `src/shim.c` (the CO-RE field accessors) to BPF bitcode and
//! hands it to bpf-linker with the Rust code. BPF target only: the host
//! build of this crate, as a build-dep of linprov, doesn't link anything.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-env-changed=CLANG");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("bpf") {
        return;
    }
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb",
        _ => "bpfel",
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set")).join("shim.bc");
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(&clang)
        .args([
            "-target",
            target,
            "-O2",
            "-g",
            "-emit-llvm",
            "-c",
            "src/shim.c",
            "-o",
        ])
        .arg(&out)
        .status()
        .unwrap_or_else(|e| panic!("running {clang:?} for the CO-RE shim: {e}"));
    assert!(status.success(), "clang failed to compile src/shim.c");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

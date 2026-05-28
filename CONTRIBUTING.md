# Contributing

## Workspace layout

| crate | what it is |
|---|---|
| `linprov` | userspace daemon (`cargo install linprov` lands here) |
| `linprov-ebpf` | BPF program source; consumed by `linprov`'s `build.rs` |
| `linprov-common` | shared types / ABI between the two (OriginRecord, AllowRule, dim flags, FNV hashing) |

`linprov-ebpf` is a regular `[build-dependencies]` entry on `linprov`. On `cargo install linprov`, cargo ships its source into the registry cache; `linprov`'s `build.rs` finds it via `linprov_ebpf::SOURCE_DIR` (a `const &str = env!("CARGO_MANIFEST_DIR")`) and runs a nested `cargo build --target bpfel-unknown-none --features bpf-build` against it.

## Versioning

Each crate owns its own `version` in its `Cargo.toml` and moves independently. SemVer applies pre-1.0 with the usual Rust convention: `0.X` is the major, `0.X.Y` is the patch.

When to bump:

- **`linprov-common`** is the on-wire ABI. **Bump `0.X` → `0.(X+1)`** on any change that alters the byte layout of `OriginRecord` / `AllowRule`, the meaning of dim flag bits, or the FNV hashing semantics. Patch bumps for docs / non-public changes only.
- **`linprov-ebpf`** is BPF program source. **Patch (`0.X.Y`)** for BPF logic / verifier-shape changes. **Minor (`0.X`)** for new map types, new features, or changes that `linprov`'s `build.rs` needs to know about.
- **`linprov`** is the daemon. **Patch** for fixes, log tweaks, docs. **Minor** for CLI surface changes (modes, flags, env vars) or new operational behavior (`linprov setup`, hot reload, etc.).

When a sibling crate's version moves: the dependent's `workspace.dependencies` entry in the root `Cargo.toml` carries a SemVer constraint (`version = "0.1.0"` → caret-implicit `^0.1.0`). A `0.X` → `0.(X+1)` bump on a dep means you must also update that constraint in the root manifest, and almost always bump the consuming crate too.

## Publishing

Three publishes from the root, in this order (each needs ~30s for the crates.io index to settle before the next dep resolves):

```sh
cargo publish -p linprov-common && sleep 30
cargo publish -p linprov-ebpf   && sleep 30
cargo publish -p linprov
```

You can skip any crate that hasn't moved version since its last publish — crates.io rejects republishing the same version.

## Dev workflow

```sh
# Format + host-target clippy + unit tests (CI parity, fast):
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Clippy linprov-ebpf for the BPF target — the host clippy only covers
# the lib stub because src/main.rs is `required-features = ["bpf-build"]`.
# Run this before pushing too; warnings in the BPF program need to fail
# CI explicitly:
cargo clippy -p linprov-ebpf \
    --target bpfel-unknown-none -Zbuild-std=core \
    --features bpf-build --bin linprov-ebpf -- -D warnings

# Full daemon attach + behavior — needs root + kernel ≥ 6.5 with BPF LSM
# active. See tests/README.md.
cargo build
sudo ./tests/smoke/run-all.sh
```

The repo's GitHub Actions CI runs `fmt` / `clippy` / `cargo test` on every push. The smoke suite isn't in CI today because GitHub-hosted runners don't ship with `bpf` in the active `lsm=` boot parameter — run it locally before merging anything that touches the BPF program, the allowlist semantics, or the kernel/userspace boundary.

## Memory: known verifier gotchas

Things to keep in mind when editing `linprov-ebpf/src/main.rs`:

- **Sleepable programs can't use LpmTrie.** We're sleepable for `bpf_get_file_xattr`, so any prefix matching has to go through hash maps (currently FNV-1a hash walks at `/` boundaries).
- **Byte-keyed map lookups inside bounded scan loops explode the 1M-insn verifier budget.** Pre-computing arrays of folder hashes was the previous shape and it didn't fit; the current code re-hashes per rule inside the rule-iteration loop because that pattern collapses verifier state better.
- **Two `SCRATCH` slots in `PerCpuArray`.** `file_open` and `bprm_check_security` are both sleepable LSM hooks; either can yield during a kfunc while the other fires on the same CPU. Don't collapse to one slot.
- **Profile knobs (`panic = "abort"`, `overflow-checks = false`, `debug = 2`) live in the workspace root.** Cargo silently ignores per-package `[profile]` blocks for workspace members. The workspace profile applies to all three crates.

## License

Userspace is `MIT OR Apache-2.0`. The BPF program declares `Dual MIT/GPL` in its `license` ELF section so the verifier accepts `gpl_only` helpers like `bpf_d_path`. See the License section in the README.

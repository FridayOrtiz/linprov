# Publishing checklist

`cargo install linprov` doesn't work until the renamed aya fork crates
are published to crates.io. This is the one-time setup, in the
correct dependency order. Each `cargo publish` needs your crates.io
API token (`cargo login` once if you haven't).

## 1. Publish the renamed aya fork

The fork lives at <https://github.com/FridayOrtiz/aya>, branch
`linprov-fork-rename`. That branch renames the seven crates linprov
consumes to `aya-friday-*` (the workspace `main` branch keeps its
upstream names so future upstream merges stay clean).

From a checkout of that branch:

```sh
# Build sanity check before publishing anything.
cargo check -p aya-friday -p aya-friday-obj
cargo check -p aya-friday-ebpf --target bpfel-unknown-none -Zbuild-std=core

# Publish in dependency order. Each command pauses for a few seconds
# after success to let the crates.io index catch up before the next
# one resolves its dep.
cargo publish -p aya-friday-build       && sleep 30
cargo publish -p aya-friday-ebpf-cty    && sleep 30
cargo publish -p aya-friday-ebpf-bindings && sleep 30
cargo publish -p aya-friday-ebpf-macros && sleep 30
cargo publish -p aya-friday-ebpf        && sleep 30
cargo publish -p aya-friday-obj         && sleep 30
cargo publish -p aya-friday
```

If a publish fails partway, fix the issue and resume from that crate
— crates.io rejects re-publishing a version that's already up, so
you can't accidentally double-publish.

## 2. Drop the `git` fallback in linprov

Once all seven `aya-friday-*` crates are live, linprov's deps can
talk to crates.io directly:

```toml
# Cargo.toml workspace.dependencies
aya = { package = "aya-friday", version = "0.13.2" }
```

```toml
# linprov/ebpf/Cargo.toml
aya-ebpf = { package = "aya-friday-ebpf", version = "0.1.2" }
```

(today these also carry `git = ... branch = "linprov-fork-rename"`;
delete those keys after step 1.)

## 3. Publish linprov-common

It's a pure library, no native deps:

```sh
cargo publish -p linprov-common
sleep 30
```

## 4. Publish linprov

```sh
cargo publish -p linprov
```

After this finishes, `cargo install linprov` works on any host with
the right toolchain — the `rust-toolchain.toml` shipped inside the
linprov tarball drives rustup to install nightly + rust-src
automatically. The user still needs `bpf-linker` (`cargo install
bpf-linker`) for the BPF object build inside the linprov build.rs.

## Subsequent releases

For an iteration where neither the aya fork nor linprov-common have
changed, you only need step 4 (with the version bumped).

If you change anything in the aya fork: bump the affected
`aya-friday-*` versions, re-run the relevant subset of step 1, then
bump linprov's dep version requirements and re-publish linprov.

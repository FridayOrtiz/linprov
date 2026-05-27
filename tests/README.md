# Smoke tests

End-to-end tests that load the BPF program against a real kernel, mark
files via HTTP downloads, and check enforcement.

## Requirements

- Linux 6.5+ with **BPF LSM enabled** (`bpf` present in
  `/sys/kernel/security/lsm`). The daemon won't attach otherwise.
- `python3`, `curl`, `sudo`, `getfattr`, `setfattr`.
- A build of the daemon at `target/debug/linprov`. `cargo build` from
  the repo root produces it.

## Run

From the repo root:

```sh
cargo build
sudo ./tests/smoke/run-all.sh
```

Each script is independent; you can run them one at a time. They all
share helpers from `tests/smoke/common.sh`.

| script | what it covers |
|---|---|
| `basic.sh` | daemon loads in observe mode; a curl download gets marked with the v3 xattr |
| `inode_storage.sh` | strip the xattr after marking — enforce still works (inode_storage path is live) |
| `xattr_fallback.sh` | restart the daemon (wiping inode_storage) — enforce still works on previously-marked files (xattr path is live) |
| `and_or.sh` | AND-within-a-rule, OR-across-rules; `landing_*` vs `target_*` distinction when the file is moved between download and exec |
| `soak.sh` | soak with default and full `--soak` CSV; output is enforce-able |

## CI

These scripts don't run on GitHub-hosted runners because those don't
ship with BPF LSM in the active `lsm=` boot parameter. The
`.github/workflows/ci.yml` runs the **unit tests** in CI; running the
smoke suite needs a self-hosted runner (or a local pass before
merging).

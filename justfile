# fishbowl-v2 task recipes. Both platforms invoke the same commands; CI calls these too.
# `just` install (Windows): winget install --id Casey.Just --scope user
# `just` install (Linux): cargo install just  OR  apt install just

VM := "fishbowl-vm"
VM_REPO := "~/src/fishbowl-v2"

default:
    @just --list

# Run all test legs (Python prototype + Rust workspace on the VM).
test: test-python test-linux

# Python prototype tests on the Windows host (no Rust dependency).
test-python:
    python prototypes/transcript_reader/tests.py

# Rust workspace tests on the Linux dev VM via SSH. Pulls latest main first.
test-linux:
    ssh {{VM}} 'cd {{VM_REPO}} && git pull --ff-only && source ~/.cargo/env && cargo test --workspace'

# Build release binary on the Linux dev VM.
build-linux:
    ssh {{VM}} 'cd {{VM_REPO}} && git pull --ff-only && source ~/.cargo/env && cargo build --release --workspace'

# Run clippy on the Linux dev VM; treat warnings as errors.
lint:
    ssh {{VM}} 'cd {{VM_REPO}} && git pull --ff-only && source ~/.cargo/env && cargo clippy --workspace --all-targets -- -D warnings'

# Format Rust on the Linux dev VM (run before commit). Modifies the VM checkout —
# remember to pull back / re-fetch on Windows if you've been editing here.
fmt:
    ssh {{VM}} 'cd {{VM_REPO}} && source ~/.cargo/env && cargo fmt --all'

# Run the daemon CLI against this session's own transcript on the VM — a quick
# end-to-end check that schema events are being emitted.
demo-transcript SESSION_JSONL:
    ssh {{VM}} 'cd {{VM_REPO}} && source ~/.cargo/env && cargo run --release --bin fishbowl -- transcript {{SESSION_JSONL}}'

#!/bin/bash
set -euo pipefail

# Build release artifacts for eShield:
# - static musl binary
# - eBPF object
# - DEB / RPM packages (if cargo-deb / cargo-generate-rpm are installed)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building eBPF object"
cargo +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release

echo "==> Building userspace static binary"
cargo build --package eshield --target x86_64-unknown-linux-musl --release

mkdir -p "$ROOT/dist"

cp "$ROOT/target/x86_64-unknown-linux-musl/release/eshield" "$ROOT/dist/eshield-x86_64-unknown-linux-musl"
cp "$ROOT/target/bpfel-unknown-none/release/eshield" "$ROOT/dist/eshield.bpf.o"

if command -v cargo-deb >/dev/null 2>&1; then
    echo "==> Building DEB package"
    cargo deb --no-build --target x86_64-unknown-linux-musl -p eshield
    cp "$ROOT/target/x86_64-unknown-linux-musl/debian/"*.deb "$ROOT/dist/"
else
    echo "==> cargo-deb not installed, skipping DEB package"
fi

if command -v cargo-generate-rpm >/dev/null 2>&1; then
    echo "==> Building RPM package"
    cargo generate-rpm --target x86_64-unknown-linux-musl -p eshield
    cp "$ROOT/target/x86_64-unknown-linux-musl/generate-rpm/"*.rpm "$ROOT/dist/"
else
    echo "==> cargo-generate-rpm not installed, skipping RPM package"
fi

echo "==> Artifacts in $ROOT/dist"
ls -lh "$ROOT/dist"

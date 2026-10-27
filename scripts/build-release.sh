#!/bin/bash
set -euo pipefail

# Build release artifacts for eShield:
# - static musl binary
# - eBPF object
# - DEB / RPM packages (if cargo-deb / cargo-generate-rpm are installed)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
EBPF_TOOLCHAIN="${ESHIELD_EBPF_TOOLCHAIN:-nightly-2026-07-31}"

echo "==> Building eBPF object"
cargo +"$EBPF_TOOLCHAIN" build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release

echo "==> Building userspace static binary"
cargo build --package eshield --target x86_64-unknown-linux-musl --release

echo "==> Building Hub binary"
cargo build --package eshield-hub --release

mkdir -p "$ROOT/dist"

cp "$ROOT/target/x86_64-unknown-linux-musl/release/eshield" "$ROOT/dist/eshield-x86_64-unknown-linux-musl"
cp "$ROOT/target/bpfel-unknown-none/release/eshield" "$ROOT/dist/eshield.bpf.o"
# publish-release.sh 期望该资产：Hub 与节点使用不同的 libc 目标（Hub 用 gnu，便于本机直接运行）
cp "$ROOT/target/release/eshield-hub" "$ROOT/dist/eshield-hub-x86_64-unknown-linux-gnu"

# 与历史 release 保持一致：同时产出 SHA256SUMS（安装脚本会做校验）
( cd "$ROOT/dist" && sha256sum eshield-x86_64-unknown-linux-musl eshield.bpf.o \
    eshield-hub-x86_64-unknown-linux-gnu > SHA256SUMS )
echo "==> SHA256SUMS"
cat "$ROOT/dist/SHA256SUMS"

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

#!/bin/bash
# 手动构建 release 二进制
set -e

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

echo "Building eBPF for bpfel-unknown-none..."
cargo +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release

echo "Building userspace for $TARGET..."
cargo build --package eshield --target "$TARGET" --release

echo "Release binary: target/$TARGET/release/eshield"

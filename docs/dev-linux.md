# eShield 开发环境

## 推荐环境

- Ubuntu 22.04 / 24.04
- Linux 内核 >= 5.10，启用 BTF
- Rust stable + nightly
- LLVM / clang
- bpf-linker

## 安装依赖

```bash
rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none --toolchain nightly
rustup target add x86_64-unknown-linux-musl

# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y llvm clang libelf-dev

# bpf-linker（推荐 cargo-binstall）
cargo install cargo-binstall
cargo binstall bpf-linker
```

## 构建

```bash
# eBPF + userspace
cargo xtask build

# 仅 eBPF
cargo xtask build-ebpf

# 发布包
bash scripts/build-release.sh
```

## 本地测试

```bash
# 单元测试
cargo test --workspace --exclude eshield-ebpf

# 集成测试（需要 root）
cargo +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release
cargo build --package eshield --target x86_64-unknown-linux-musl --release
sudo bash tests/netns_test.sh
```

## Windows 开发者

Aya 用户态依赖 Linux API，**无法直接在 Windows 上构建运行**。请在 WSL2 / 虚拟机 / 远程 Linux 上构建。

代码编辑可在 Windows 完成；构建与测试必须在 Linux 环境执行。

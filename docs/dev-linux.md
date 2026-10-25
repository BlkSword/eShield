# eShield 开发环境

## 推荐环境

- Ubuntu 22.04 / 24.04 / 26.04
- Linux 内核 >= 5.10，启用 BTF
- Rust stable + nightly（默认 `nightly-2026-07-31`）
- LLVM / clang
- bpf-linker **`0.10.4`**（必须与 nightly 工具链匹配，见下方“工具链兼容性”）

## 安装依赖

```bash
rustup toolchain install nightly-2026-07-31 --profile minimal --component rust-src
rustup target add x86_64-unknown-linux-musl
# 注意：bpfel-unknown-none 是 tier-3 目标，由 `-Z build-std=core` 现场构建，
# 不需要（也无法）用 rustup target add 安装。
rustup target add bpfel-unknown-none --toolchain nightly-2026-07-31 2>/dev/null || true

# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y llvm clang libelf-dev musl-tools zstd
# musl 静态构建时 cc-rs 需要 x86_64-linux-musl-gcc
sudo ln -sf /usr/bin/musl-gcc /usr/local/bin/x86_64-linux-musl-gcc

# bpf-linker：优先用官方预编译包（资产后缀是 .tar.zst），避免本地 LLVM 版本踩坑
curl -fsSL -o /tmp/bl.tar.zst \
  https://github.com/aya-rs/bpf-linker/releases/download/v0.10.4/bpf-linker-x86_64-unknown-linux-musl.tar.zst
zstd -d -f /tmp/bl.tar.zst -o /tmp/bl.tar
sudo tar -xf /tmp/bl.tar -C /usr/local/bin
bpf-linker --version
```

## 工具链兼容性（重要）

- **bpf-linker 版本必须与 nightly 匹配**。实测在 `nightly-2026-07-31` + 内核 7.0 上：
  - `bpf-linker 0.10.4`（项目固定版本）：eBPF 程序通过 verifier 并正常挂载；
  - `bpf-linker 0.12.0`：生成的代码被 verifier 拒绝，报
    `R11 is invalid`（`*(u64 *)(r11 -8) = ...` 非法栈写），
    `cargo` 构建完全正常，只有真正 `attach` 时才暴露。
  因此**不要用 `cargo binstall bpf-linker` 拿最新版**，也不要在 CI 里用 `latest`。
- 由于 verifier 只在 attach 时校验，改完数据面务必跑一次集成测试或用下面的最小挂载脚本验证，
  不能以“编译通过”作为通过标准。

### 最小挂载自检（可选）

```bash
ip link add dummy-esh type dummy && ip link set dummy-esh up
sudo ESHIELD_XDP_MODE=skb ./target/x86_64-unknown-linux-musl/release/eshield start \
  --config <(printf 'interface="dummy-esh"\nweb_bind="127.0.0.1:18888"\n')
# 日志出现 "attaching generic XDP" / "eShield is running on" 即表示 verifier 通过
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

# 集成测试（需要 root；SKIP_BUILD=1 复用已构建产物）
cargo +nightly-2026-07-31 build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release
cargo build --package eshield --target x86_64-unknown-linux-musl --release
sudo SKIP_BUILD=1 ESHIELD_TEST_XDP_MODE=skb bash tests/netns_test.sh

# SYN Proxy 对带 TCP 选项 SYN 的兜底丢弃（需要 hping3）
sudo SKIP_BUILD=1 bash tests/syn_proxy_options_test.sh
```

> 集成测试脚本会自动探测 cargo 路径（sudo 重置 PATH 也能用），
> 并在退出时恢复宿主机的 `/var/lib/eshield/rules.redb`，不会清掉已有动态规则。

## Windows 开发者

Aya 用户态依赖 Linux API，**无法直接在 Windows 上构建运行**。请在 WSL2 / 虚拟机 / 远程 Linux 上构建。

代码编辑可在 Windows 完成；构建与测试必须在 Linux 环境执行。

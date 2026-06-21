# eShield

基于 **eBPF/XDP** 的**主机级 CC 防御盾**。

> 当 Cloudflare 太贵、iptables 太慢、商业 WAF 太重时，eShield 是独立开发者与小站长能负担得起的最后一道主机防线——单二进制、一键启动、在 XDP 层把 CC 流量挡在内核协议栈之外。

## 核心特性

- 内核态 eBPF/XDP 包过滤，**10–50 倍于 iptables** 的性能
- Per-IP 指数衰减滑动窗口速率限制
- SYN Cookie 代理，防御 SYN Flood
- L7 轻量指纹扫描
- CIDR 白名单 / 动态黑名单
- TUI + Web Dashboard 双观测面
- 单二进制静态链接，一键安装
- 配置热加载，无需重启

## 技术栈

- 内核态：Rust + Aya + eBPF/XDP
- 用户态：Rust + Tokio + axum + ratatui
- 观测：Prometheus /metrics、结构化日志
- 部署：systemd + curl | bash

## 快速开始

### 环境要求

- **Linux 环境**（物理机 / 虚拟机 / 云主机 / WSL2）
- Linux 内核 >= 5.10，启用 BTF（`/sys/kernel/btf/vmlinux` 存在）
- Rust >= 1.70（nightly + bpf target）
- LLVM / clang（Aya 编译 eBPF 需要）

> ⚠️ **Windows 开发者注意**：Aya 用户态库依赖 `std::os::fd` 等 Linux 特有 API，因此**无法在 Windows 上直接编译或运行**。请在 WSL2 / 虚拟机 / 云主机上进行构建和测试。代码可以在 Windows 上编辑，但构建与运行必须在 Linux 环境。

### 构建

```bash
# 安装 Rust nightly + bpf target
rustup toolchain install nightly
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly

# 安装 bpf-linker（推荐）或配置 rust-lld
cargo install bpf-linker

# 构建 eBPF + 用户态
cargo xtask build

# 运行（需要 root / CAP_BPF / CAP_NET_ADMIN）
sudo cargo xtask run --iface eth0
```

### 一键安装

```bash
curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo bash
```

### 从源码构建安装

```bash
sudo bash scripts/install.sh --build
```

### 服务管理

```bash
sudo systemctl status eshield
sudo systemctl reload eshield   # SIGHUP 热加载配置
sudo journalctl -u eshield -f
```

## 文档

- [技术设计方案](eShield_design_utf8enc.txt)
- [架构设计](docs/architecture.md)（待补充）
- [部署指南](docs/deployment.md)
- [基准测试](docs/benchmark.md)

## 定位声明

eShield 是**主机级 CC 防御盾**，不是万能 DDoS 银弹。它无法对抗 T 级带宽耗尽型攻击（云厂商黑洞机制是物理天花板），但能在"带宽没满、CPU/连接数被耗尽"的 CC 场景下提供极低成本的防护。

## License

Apache-2.0

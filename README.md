# eShield

[English](README_EN.md) | 中文

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

基于 **eBPF/XDP** 的主机级 L3-L4 网络清洗盾，专注防御 SYN/UDP/ICMP Flood、CC、扫段等网络层攻击。

---

## 目录

- [项目简介](#项目简介)
- [核心能力](#核心能力)
  - [性能](#性能)
  - [攻击者成本](#攻击者成本)
- [核心特性](#核心特性)
- [架构概览](#架构概览)
- [快速开始](#快速开始)
  - [环境要求](#环境要求)
  - [构建与安装](#构建与安装)
  - [服务管理](#服务管理)
- [配置与使用](#配置与使用)
  - [CLI 子命令](#cli-子命令)
  - [认证说明](#认证说明)
  - [配置文件](#配置文件)
  - [热加载](#热加载)
- [观测面](#观测面)
- [API 与文档](#api-与文档)
- [测试](#测试)
- [项目结构](#项目结构)
- [定位与限制](#定位与限制)
- [License](#license)

---

## 项目简介

eShield 在 Linux 内核 XDP 钩子上运行一个由 Rust/Aya 编写的 eBPF 程序，将恶意流量在进入内核网络协议栈之前拦截。控制面使用 Rust + Tokio + axum 提供中文 Web Dashboard、REST API、CLI、TUI、审计日志、持久化与告警能力。

与传统 iptables/nftables 相比，eShield 的决策点位于网卡驱动层，具备更低的延迟、更高的包处理吞吐，以及对 SYN Flood / UDP Flood / ICMP Flood 等网络层攻击更强的压制能力。

---

## 核心能力

### 性能

- **内核态包处理**：过滤逻辑直接在 eBPF/XDP 中运行，不经过用户态网络栈，无上下文切换、无数据拷贝。
- **微秒级延迟**：正常流量仅增加一次 eBPF Map 查表和规则匹配开销，典型延迟增加小于 1 µs。
- **高吞吐**：在普通 VM + veth 单核测试环境中，XDP PASS 路径可达约 **24 万 pps**；物理网卡配合多队列/RSS 可扩展至数百万 pps。
- **低开销**：eBPF 程序 JIT 编译为本地机器码，命中黑名单/ACL 的包被硬件级早 drop。
- **单二进制静态链接**：musl 静态编译，仅需一个 `eshield` 可执行文件，无额外运行时依赖。

> 详细基准测试方法见 [docs/benchmark.md](docs/benchmark.md)。

### 攻击者成本

由于 eShield 在流量最早期拦截，攻击方要产生有效压力必须付出真实成本：

- **真实带宽**：每一个被丢弃的包都会实际占用攻击者的出口带宽。
- **真实源 IP**：黑名单、GeoIP、威胁情报、自适应阈值均基于源 IP 累计。
- **完整协议交互**：SYN Cookie 代理要求每个伪造源都必须完成完整的三次握手。
- **持续人力与计算**：自适应引擎会自动对重复触发规则的源提升封禁时长。

简言之，eShield 将“攻防成本比”向防御方倾斜：防御方的一次 map 查表，可抵消攻击方的一个完整网络包、一个真实源地址以及一次协议交互。

---

## 核心特性

| 特性 | 说明 |
|---|---|
| eBPF/XDP 早期过滤 | 包处理发生在网卡驱动层，延迟远低于 iptables/nftables。 |
| CIDR 白名单 | 基于 LPM Trie，支持 IPv4/IPv6 CIDR。 |
| 动态黑名单 | LRU Hash 存储命中防御策略的源 IP，到期自动解封。 |
| Per-IP 速率限制 | 指数衰减滑动窗口，识别突发 CC 流量。 |
| UDP / ICMP Flood 防护 | 对无连接流量做 per-IP 速率抑制。 |
| 端口/协议 ACL | 支持 `tcp`/`udp`/`icmp`/`icmpv6`/`any`，端口、范围或 `any`，动作 `allow`/`drop`。 |
| SYN Cookie 代理 | IPv4 TCP SYN Flood 场景下回复 SYN-ACK Cookie，合法 ACK 验证后放行。 |
| TCP RST 回包 | 对丢弃的 TCP 连接立即回复 RST，避免客户端重传堆积。 |
| GeoIP / ASN 过滤 | 基于自定义 CSV CIDR 列表按国家或 ASN 放行/封禁。 |
| 威胁情报联动 | 定时同步自定义 URL feed，自动拦截已知恶意 IP。 |
| L7 轻量指纹扫描 | 检查 TCP 载荷前若干字节，匹配特征即 DROP。 |
| 自适应阈值引擎 | 重复触发规则的 IP 自动提升为更长时间封禁。 |
| 防护项目分组 | 按协议 + 端口 + 目标 IP 分组配置策略，控制面持久化并通过 Dashboard/API 管理。 |
| 运行时控制 | REST API + 中文 Web Dashboard + CLI + TUI，实时开关与调参。 |
| 配置热加载 | `SIGHUP` 或 `systemctl reload` 重载配置，无需重启。 |
| 认证 / 审计 / 持久化 | 可选 Bearer Token；审计日志；动态规则持久化到 redb。 |
| 可观测性 | Prometheus `/metrics`、JSON 统计、审计 SSE、TOP 攻击源。 |

> **关于防护项目**：当前版本中，防护项目作为控制面策略分组被加载、校验、持久化并展示在 Dashboard/API 中；受 XDP verifier 组合栈 512 字节限制，暂不在 eBPF 数据面对每条连接按项目独立匹配。全局防御模块仍照常生效。

---

## 架构概览

```text
┌─────────────────────────────────────────────────────────────┐
│ 管理面                                                       │
│ Web Dashboard (axum) │ TUI (ratatui) │ CLI (clap)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ REST API / Config Watch
┌──────────────────────────────▼──────────────────────────────┐
│ 控制面 — Rust 用户态                                         │
│ 配置管理 │ 事件消费 │ 自适应阈值 │ 持久化 │ 指标聚合         │
└──────────────────────────────┬──────────────────────────────┘
                               │ BPF Maps / Ring Buffer
┌──────────────────────────────▼──────────────────────────────┐
│ 数据面 — eBPF/XDP 内核态                                     │
│ 包解析 → 白名单 → 端口 ACL → GeoIP → SYN Proxy → UDP/ICMP   │
│ Flood → L7 扫描 → 速率限制 → 黑名单 → 决策                   │
└─────────────────────────────────────────────────────────────┘
```

详细设计、数据包旅程与 BPF Maps 说明见 [docs/architecture.md](docs/architecture.md)。

---

## 快速开始

### 环境要求

- Linux 内核 >= **5.10**，且启用 **BTF**：
  ```bash
  ls /sys/kernel/btf/vmlinux
  ```
- root 权限或 capabilities：`CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_PERFMON`、`CAP_IPC_LOCK`
- Rust >= 1.70（nightly + bpf target）
- LLVM / clang（Aya 编译 eBPF 需要）

> **Windows 开发者注意**：Aya 用户态库依赖 Linux 特有 API，因此**无法在 Windows 上直接编译或运行**。请在 WSL2 / 虚拟机 / 云主机上进行构建和测试。

### 构建与安装

```bash
sudo bash scripts/install.sh --build
```

这会：
1. 使用 nightly 工具链编译 eBPF 程序
2. 使用 musl target 静态编译用户态二进制
3. 将 `eshield` 安装到 `/usr/local/bin`
4. 创建默认配置 `/etc/eshield/config.toml`
5. 安装并启用 systemd 服务

也可直接下载预编译二进制，详见 [docs/deployment.md](docs/deployment.md)。

### 服务管理

```bash
sudo systemctl status eshield
sudo systemctl start eshield
sudo systemctl stop eshield
sudo systemctl restart eshield
sudo systemctl reload eshield   # SIGHUP 热加载
sudo journalctl -u eshield -f
```

---

## 配置与使用

### CLI 子命令

```bash
# 启动守护进程
sudo eshield start --config /etc/eshield/config.toml

# 查看状态（CLI 在本机运行，无需 token）
eshield status

# 实时封禁 IP（0 秒表示永久）
eshield block 192.0.2.1 --duration 300

# 实时解封 IP
eshield unblock 192.0.2.1

# 重新加载配置文件
eshield reload

# 校验配置文件
eshield check --config /etc/eshield/config.toml

# 启动 TUI 仪表盘
eshield tui

# 指定远程 API 端点
eshield status --endpoint http://eshield-host:8443
eshield block 192.0.2.1 --endpoint http://eshield-host:8443

# 重置控制台访问令牌（本机 CLI 无需旧 token）
eshield reset-token
```

### 认证说明

- 未设置 `api_token` 时，外部 Web 访问默认无需认证；设置后，外部访问 Dashboard、`/api/*`、`/metrics` 需要在请求头携带 `Authorization: Bearer <token>`。
- CLI 在本机运行时来源地址为 `127.0.0.1/::1`，自动跳过 token 校验，无需提供 `--token`。

### 配置文件

默认路径 `/etc/eshield/config.toml`，完整示例见 [packaging/config.example.toml](packaging/config.example.toml)。关键段说明：

| 配置段 | 作用 |
|---|---|
| `interface` / `web_bind` | 挂载 XDP 的网卡与 Web/API 监听地址 |
| `whitelist` / `blacklist` | 启动时加载的静态 CIDR 白名单与永久黑名单 |
| `[rate_limit]` | per-IP 速率限制与触封时长 |
| `[syn_proxy]` | IPv4 SYN Cookie 代理开关 |
| `[udp_flood]` / `[icmp_flood]` | 无连接 Flood 防护开关 |
| `[l7_scan]` | TCP 首包指纹匹配 |
| `[adaptive]` | 重复触发自动提升封禁时长 |
| `[geoip]` | 基于国家/ASN 的 CIDR 放行/封禁 |
| `[threat_intel]` | 自定义威胁情报 feed 同步 |
| `[port_acl]` | 端口/协议级 allow/drop 规则 |
| `[protection_projects]` | 控制面策略分组 |

### 热加载

修改 `/etc/eshield/config.toml` 后：

```bash
sudo systemctl reload eshield
# 或
sudo kill -HUP $(pidof eshield)
```

日志中出现 `config reloaded successfully` 即表示生效，无需重启。

---

## 观测面

### Web Dashboard

启动后访问 `http://<host>:8443/`，中文界面展示实时包统计、各防御模块命中数、TOP 攻击源、审计日志，并提供实时控制表单。

### Prometheus 指标

```
http://<host>:8443/metrics
```

主要指标包括 `eshield_dropped_total`、`eshield_passed_total`、`eshield_blacklist_blocked_total`、`eshield_rate_limited_total`、`eshield_geoip_blocked_total` 等。

### JSON 统计接口

```bash
curl -H "Authorization: Bearer <token>" http://<host>:8443/api/stats | jq
```

### TUI 仪表盘

```bash
eshield tui
```

### 审计日志

- `GET /api/audit` 查询审计事件，支持 `limit`、`ip`、`action`、`from`、`to` 过滤。
- `GET /api/audit/stream` SSE 实时推送审计事件。

---

## API 与文档

REST API 完整端点、请求/响应示例与认证说明见 [docs/api.md](docs/api.md)。

其他文档索引：

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 系统架构、数据包旅程、BPF Maps |
| [docs/deployment.md](docs/deployment.md) | 二进制、systemd、容器与 K8s 部署 |
| [docs/operations.md](docs/operations.md) | 日常操作、日志、告警、备份恢复、故障排查 |
| [docs/dev-linux.md](docs/dev-linux.md) | 依赖安装、构建、本地测试 |
| [docs/benchmark.md](docs/benchmark.md) | 基准测试方法与示例报告 |

---

## 测试

### 单元测试

```bash
cargo test --workspace --exclude eshield-ebpf
```

### 集成测试

需要 root，在 network namespace 中运行场景测试：

```bash
sudo bash ./tests/netns_test.sh
sudo bash ./tests/full_attack_test.sh
```

覆盖：黑名单、TCP RST 回包、速率限制、SYN Flood、UDP Flood、ICMP Flood、L7 指纹、服务停止后恢复、SIGHUP 热加载、自适应阈值、GeoIP/ASN、威胁情报。

### 基准测试

```bash
cargo build --package eshield --target x86_64-unknown-linux-musl --release
sudo bash scripts/benchmark.sh
```

详见 [docs/benchmark.md](docs/benchmark.md)。

---

## 项目结构

```text
.
├── eshield/            # 用户态控制面
├── eshield-ebpf/       # 内核态 eBPF/XDP 数据面
├── eshield-common/     # 内核/用户态共享结构体
├── xtask/              # 构建任务封装
├── scripts/            # install.sh / uninstall.sh / benchmark.sh
├── tests/              # 集成测试脚本
├── docs/               # 架构、部署、开发环境、API、基准测试文档
├── packaging/          # systemd 服务、deb/rpm 配置、示例配置
├── README.md
├── README_EN.md
└── LICENSE
```

---

## 定位与限制

- **主机级网络清洗盾**：面向“带宽没满、但连接/包处理被耗尽”的 SYN/UDP/ICMP Flood 与 CC 场景。
- **不是 DDoS 银弹**：T 级带宽耗尽型攻击需要云厂商黑洞/清洗，eShield 无法突破物理网络天花板。
- **SYN Cookie 代理**：当前仅支持 IPv4 TCP；启用后所有 SYN 都会受到 Cookie 挑战。
- **L7 扫描**：仅检查 TCP 首包，适合首包即携带完整特征的场景；不支持 TCP 分段重组。
- **Windows**：无法直接编译或运行，请使用 Linux 环境。
- **防护项目**：当前为控制面配置分组，尚未在 eBPF 数据面按项目逐包匹配。

---

## License

Apache-2.0

# eShield

基于 **eBPF/XDP** 的主机级 CC / L3-L4 防御盾。   
A host-level CC and L3-L4 defense shield powered by **eBPF/XDP**.

单二进制、内核态过滤、REST API + Web Dashboard + CLI 控制。   
Single static binary, kernel-space filtering, controlled via REST API, Web Dashboard, and CLI.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 目录 / Table of Contents

- [简介 / Introduction](#简介--introduction)
- [核心特性 / Core Features](#核心特性--core-features)
- [架构概览 / Architecture](#架构概览--architecture)
- [快速开始 / Quick Start](#快速开始--quick-start)
- [配置与使用 / Configuration & Usage](#配置与使用--configuration--usage)
- [观测面 / Observability](#观测面--observability)
- [API 概览 / API Overview](#api-概览--api-overview)
- [测试 / Testing](#测试--testing)
- [项目结构 / Project Structure](#项目结构--project-structure)
- [定位与限制 / Positioning & Limitations](#定位与限制--positioning--limitations)
- [文档 / Documentation](#文档--documentation)
- [License](#license)

---

## 简介 / Introduction

eShield 在 Linux 内核 XDP 钩子上运行一个 Rust/Aya 编写的 eBPF 程序，将恶意流量在进入内核协议栈之前拦截。控制面使用 Rust + Tokio + axum 提供 Web Dashboard、REST API、CLI、TUI、审计日志、持久化与告警能力。

eShield runs a Rust/Aya eBPF program on the Linux XDP hook to drop malicious traffic before it enters the kernel networking stack. The userspace control plane is built with Rust, Tokio, and axum, providing a Web Dashboard, REST API, CLI, TUI, audit log, persistence, and alerting.

---

## 核心特性 / Core Features

| 特性 Feature | 说明 Description |
|---|---|
| eBPF/XDP 早期过滤 | 包处理发生在网卡驱动层，延迟远低于 iptables/nftables。 Packet processing happens at the NIC driver layer, with much lower latency than iptables/nftables. |
| CIDR 白名单 | 基于 LPM Trie，支持 IPv4/IPv6 CIDR。 LPM-Trie based whitelist supporting IPv4/IPv6 CIDRs. |
| 动态黑名单 | LRU Hash 存储命中防御策略的源 IP，到期自动解封。 LRU hash for dynamic blacklisting with automatic expiry. |
| Per-IP 速率限制 | 指数衰减滑动窗口，识别突发 CC 流量。 Exponential-decay sliding-window rate limiting per source IP. |
| UDP / ICMP Flood 防护 | 对无连接流量做 per-IP 速率抑制。 Per-IP rate suppression for UDP and ICMP/ICMPv6 floods. |
| 端口/协议 ACL | 支持 `tcp`/`udp`/`icmp`/`icmpv6`/`any`，端口、范围或 `any`，动作 `allow`/`drop`。 Protocol/port ACLs with ranges, `any`, and `allow`/`drop` actions. |
| SYN Cookie 代理 | IPv4 TCP SYN Flood 场景下回复 SYN-ACK Cookie，合法 ACK 验证后放行。 SYN Cookie proxy for IPv4 TCP SYN flood mitigation. |
| HTTP WAF 规则引擎 | 解析 TCP 首包，支持 method / path_prefix / host / user_agent / body_prefix 匹配。 TCP-first-packet HTTP WAF matching method, path, host, UA, and body prefix. |
| JS Challenge | WAF `challenge` 动作拦截请求，完成 `/challenge` 验证后加入临时白名单。 JS challenge with temporary allowlist on success. |
| GeoIP / ASN 过滤 | 基于自定义 CSV CIDR 列表按国家或 ASN 放行/封禁。 GeoIP/ASN filtering via custom CSV CIDR lists. |
| 威胁情报联动 | 定时同步自定义 URL feed，自动拦截已知恶意 IP。 Periodic threat-intel feed synchronization. |
| L7 轻量指纹扫描 | 检查 TCP 载荷前 64 字节，匹配特征即 DROP。 Lightweight L7 fingerprint scan on first 64 bytes of TCP payload. |
| 自适应阈值引擎 | 重复触发规则的 IP 自动提升为更长时间封禁。 Adaptive threshold engine for escalating repeat offenders. |
| 防护项目分组 | 按协议 + 端口 + 目标 IP 分组配置策略，控制面持久化并通过 Dashboard/API 管理。 Protection projects group policies by protocol/port/target IP and are persisted in the control plane. |
| 运行时控制 | REST API + 中文 Web Dashboard + CLI，实时开关与调参。 Runtime control via REST API, Chinese Web Dashboard, and CLI. |
| 配置热加载 | `SIGHUP` 或 `systemctl reload` 重载配置，无需重启。 Config hot-reload via `SIGHUP` without restart. |
| 认证 / 审计 / 持久化 | 可选 Bearer Token；审计日志；动态规则持久化到 redb。 Optional Bearer token, audit log, and dynamic rule persistence with redb. |
| 可观测性 | Prometheus `/metrics`、JSON 统计、审计 SSE、TOP 攻击源、中文 TUI。 Prometheus metrics, JSON stats, audit SSE, top attackers, Chinese TUI. |
| 单二进制静态链接 | musl 静态编译，仅依赖一个 `eshield` 可执行文件。 Static musl binary; only the `eshield` executable is required. |

> **关于防护项目 / About protection projects**: 当前版本中，防护项目作为控制面策略分组被加载、校验、持久化并展示在 Dashboard/API 中；受 XDP verifier 组合栈 512 字节限制，暂不在 eBPF 数据面对每条连接按项目独立匹配。全局防御模块仍照常生效。  
> In the current version, protection projects are loaded, validated, persisted, and exposed via the Dashboard/API. Due to the XDP verifier's 512-byte combined stack limit, per-project packet matching in the eBPF data path is not yet enabled; global defense modules remain active.

---

## 架构概览 / Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ 管理面 / Management Plane                                   │
│ Web Dashboard (axum) │ TUI (ratatui) │ CLI (clap)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ REST API / Config Watch
┌──────────────────────────────▼──────────────────────────────┐
│ 控制面 / Control Plane — Rust 用户态 / userspace              │
│ 配置管理 │ 事件消费 │ 自适应阈值 │ 持久化 │ 指标聚合         │
└──────────────────────────────┬──────────────────────────────┘
                               │ BPF Maps / Ring Buffer
┌──────────────────────────────▼──────────────────────────────┐
│ 数据面 / Data Plane — eBPF/XDP 内核态 / kernel-space          │
│ 包解析 → 白名单 → 端口 ACL → GeoIP → SYN Proxy → UDP/ICMP   │
│ Flood → L7 扫描 → WAF → 速率限制 → 黑名单 → 决策             │
└─────────────────────────────────────────────────────────────┘
```

详细设计见 [docs/architecture.md](docs/architecture.md)。   
See [docs/architecture.md](docs/architecture.md) for detailed design.

---

## 快速开始 / Quick Start

### 环境要求 / Requirements

- Linux 内核 >= **5.10**，且启用 **BTF**：
  ```bash
  ls /sys/kernel/btf/vmlinux
  ```
- root 权限或 capabilities：`CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_PERFMON`、`CAP_IPC_LOCK`
- Rust >= 1.70（nightly + bpf target）
- LLVM / clang（Aya 编译 eBPF 需要）

> **Windows 开发者注意**：Aya 用户态库依赖 Linux 特有 API，因此**无法在 Windows 上直接编译或运行**。请在 WSL2 / 虚拟机 / 云主机上进行构建和测试。  
> **Windows developers**: Aya userspace code relies on Linux-specific APIs, so you **cannot build or run eShield directly on Windows**. Use WSL2, a VM, or a Linux cloud host.

### 一键安装 / One-line install

```bash
curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo bash
```

指定版本 / Pin a version:

```bash
VERSION=0.2.0 curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo VERSION=0.2.0 bash
```

### 从源码构建 / Build from source

```bash
sudo bash scripts/install.sh --build
```

这会：
1. 使用 nightly 工具链编译 eBPF 程序
2. 使用 musl target 静态编译用户态二进制
3. 将 `eshield` 安装到 `/usr/local/bin`
4. 创建默认配置 `/etc/eshield/config.toml`
5. 安装并启用 systemd 服务

This will compile the eBPF program with the nightly toolchain, build a static musl userspace binary, install `eshield` to `/usr/local/bin`, create the default config, and enable the systemd service.

### 服务管理 / Service management

```bash
sudo systemctl status eshield
sudo systemctl start eshield
sudo systemctl stop eshield
sudo systemctl restart eshield
sudo systemctl reload eshield   # SIGHUP 热加载 / hot-reload
sudo journalctl -u eshield -f
```

---

## 配置与使用 / Configuration & Usage

### CLI 子命令 / CLI commands

```bash
# 启动守护进程 / Start daemon
sudo eshield start --config /etc/eshield/config.toml

# 查看状态 / Show status
eshield status

# 实时封禁 IP（0 秒表示永久）/ Block an IP (0 = permanent)
eshield block 192.0.2.1 --duration 300

# 实时解封 IP / Unblock an IP
eshield unblock 192.0.2.1

# 重新加载配置文件 / Reload config file
eshield reload

# 校验配置文件 / Validate config file
eshield check --config /etc/eshield/config.toml

# 启动 TUI 仪表盘 / Launch TUI dashboard
eshield tui

# 指定远程 API 端点 / Use a remote API endpoint
eshield status --endpoint http://eshield-host:8443
eshield block 192.0.2.1 --endpoint http://eshield-host:8443
```

### 配置文件 / Configuration file

默认路径 `/etc/eshield/config.toml`：

```toml
# 要挂载 XDP 的网卡 / Network interface for XDP
interface = "eth0"

log_level = "info"          # trace/debug/info/warn/error
log_json = false            # 是否以 JSON 格式输出日志 / Output logs as JSON
ebpf_log_enabled = false    # eBPF 内核调试日志开关 / eBPF kernel debug logging

udp_flood_enabled = false   # UDP Flood 防护 / UDP flood protection
icmp_flood_enabled = false  # ICMP/ICMPv6 Flood 防护 / ICMP flood protection
tcp_reset_on_drop = false   # 对丢弃的 TCP 连接回复 RST / Reply TCP RST on drop

web_bind = "0.0.0.0:8443"   # Web / API / Prometheus 监听地址
# api_token = "changeme"    # 可选 API 认证 / Optional API token

store_path = "/var/lib/eshield/rules.redb"  # 动态规则持久化 / Dynamic rule store

# 告警 Webhook（可选）/ Alert webhook (optional)
# alert_webhook_url = "https://hooks.example.com/eshield"
alert_webhook_type = "generic"   # generic / slack / dingtalk / wecom
alert_threshold_dps = 1000
alert_cooldown_s = 60

# 白名单 CIDR / Whitelist CIDRs
whitelist = ["127.0.0.1/32", "10.0.0.0/8"]

# 黑名单 IP/CIDR（启动时加载，永久封禁）/ Static blacklist
blacklist = ["192.0.2.1"]

[rate_limit]
enabled = true
threshold = 200             # 每个 tick 允许的最大包数 / Max packets per tick
tick_ms = 100               # 计数窗口 / Tick window
decay_num = 7
decay_den = 8               # 指数衰减因子 / Exponential decay factor
block_duration_s = 300      # 触发后封禁时长 / Block duration after trigger

[syn_proxy]
enabled = false             # SYN Cookie 代理 / SYN Cookie proxy

[l7_scan]
enabled = false
patterns = [
    { pattern = "ATTACKER" },
]

[adaptive]
enabled = true
threshold = 10              # 窗口内触发次数 / Hits in window
window_s = 5
block_duration_s = 300

[waf]
enabled = false
# action: drop / log / challenge
rules = [
    { name = "block-admin", enabled = true, priority = 1, action = "drop", match = { method = "GET", path_prefix = "/admin" } },
    { name = "challenge-secret", enabled = true, priority = 2, action = "challenge", match = { method = "GET", path_prefix = "/secret" } },
]

[challenge]
enabled = true              # 需与 waf challenge action 配合
mode = "js"                 # js / 302（当前仅实现 js）
ttl_s = 3600                # 临时白名单有效期 / Temp allowlist TTL

[geoip]
enabled = false
# db_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"  # MaxMind MMDB（预留 / reserved）
country_blocks_csv = "/etc/eshield/geoip_country.csv"
# asn_blocks_csv = "/etc/eshield/geoip_asn.csv"
block_countries = ["XX"]
# allow_countries = ["CN"]
# block_asns = [12345]
# allow_asns = []
default_action = "pass"

[threat_intel]
enabled = false
# [[threat_intel.feeds]]
# name = "abuseipdb"
# url = "https://api.abuseipdb.com/api/v2/blacklist"
# interval_s = 3600
# action = "drop"
# confidence = 80

# 端口/协议 ACL / Protocol/port ACL
# [[port_acl]]
# protocol = "tcp"
# dport = "22"
# action = "allow"

# 防护项目 / Protection projects (控制面分组 / control-plane grouping)
# [[protection_projects]]
# name = "web-service"
# description = "Protect public HTTP service"
# protocol = "tcp"
# dport = "80"
# target_ips = ["10.0.0.10"]
# enabled_modules = ["rate_limit", "waf", "challenge"]
# action = "defend"   # pass / drop / defend
```

### 热加载 / Hot reload

修改 `/etc/eshield/config.toml` 后：

```bash
sudo systemctl reload eshield
# 或 / or
sudo kill -HUP $(pidof eshield)
```

日志中出现 `config reloaded successfully` 即表示生效，无需重启。

---

## 观测面 / Observability

### Web Dashboard

启动后访问：

```
http://<host>:8443/
```

中文界面展示实时包统计、各防御模块命中数、TOP 攻击源、审计日志，并提供实时控制表单：

- 封禁 / 解封 IPv4/IPv6
- 放行 / 移除 IPv4/IPv6 CIDR
- 启用/禁用各防御模块、调整速率限制参数
- 实时开关 eBPF 调试日志、TCP RST 回包
- 管理 WAF 规则、端口 ACL、L7 指纹、GeoIP、威胁情报 feed
- 管理防护项目分组
- 输入 API Token（启用认证时）
- 一键重载配置文件

### Prometheus 指标 / Prometheus metrics

```
http://<host>:8443/metrics
```

暴露的主要指标：

- `eshield_dropped_total`
- `eshield_passed_total`
- `eshield_blacklist_blocked_total`
- `eshield_rate_limited_total`
- `eshield_syn_flood_blocked_total`
- `eshield_l7_blocked_total`
- `eshield_adaptive_blocked_total`
- `eshield_udp_flood_blocked_total`
- `eshield_icmp_flood_blocked_total`
- `eshield_waf_blocked_total`
- `eshield_geoip_blocked_total`
- `eshield_challenge_issued_total`
- `eshield_dropped_by_protocol_total{protocol="tcp|udp|icmp|other"}`
- `eshield_dropped_by_port_total{port="..."}`
- `eshield_source_dropped_total{ip="..."}`
- `eshield_event_consumer_duration_us_*`
- `eshield_map_max_entries{name="..."}`
- `eshield_map_entries{name="..."}`

### JSON 统计接口 / JSON stats

```bash
curl http://<host>:8443/api/stats | jq
```

### TUI 仪表盘 / TUI dashboard

```bash
eshield tui
```

中文界面，显示总丢弃、各规则拦截数、TOP 攻击源；按 `q` 退出。

### 审计日志 / Audit log

- `GET /api/audit` 查询审计事件，支持 `limit`、`ip`、`action`、`from`、`to` 过滤。
- `GET /api/audit/stream` SSE 实时推送审计事件。

---

## API 概览 / API Overview

| 端点 Endpoint | 方法 Methods | 说明 Description |
|---|---|---|
| `/healthz` | GET | 健康检查 / Health check |
| `/ready` | GET | 就绪检查 / Readiness check |
| `/challenge` | GET | JS Challenge 页面 / JS challenge page |
| `/api/challenge/pass` | POST | 提交 challenge 答案 / Submit challenge answer |
| `/` | GET | Web Dashboard |
| `/api/stats` | GET | 运行统计 / Runtime stats |
| `/api/config` | GET, PATCH | 读取/修改运行时配置 / Read/patch runtime config |
| `/api/config/reload` | POST | 从文件重新加载配置 / Reload config from file |
| `/api/protection-modules` | GET | 防护模块列表与状态 / Protection module list |
| `/api/blacklist` | POST, DELETE | 封禁/解封 IP / Block/unblock IP |
| `/api/whitelist` | POST, DELETE | 添加/移除 CIDR 白名单 / Allow/disallow CIDR |
| `/api/audit` | GET | 审计日志 / Audit log |
| `/api/audit/stream` | GET | 审计日志 SSE / Audit SSE |
| `/api/metrics/series` | GET | 时序指标 / Time-series metrics |
| `/api/metrics/attacker-series` | GET | 单 IP 时序 / Per-IP time series |
| `/api/waf/rules` | GET, POST | WAF 规则 CRUD / WAF rules |
| `/api/waf/rules/reorder` | POST | WAF 规则排序 / Reorder WAF rules |
| `/api/port-acl` | GET, POST | 端口 ACL / Port ACL |
| `/api/protection-projects` | GET, POST | 防护项目 / Protection projects |
| `/api/l7-patterns` | GET, POST | L7 指纹 / L7 patterns |
| `/api/geoip/reload` | POST | 重新加载 GeoIP CSV / Reload GeoIP CSV |
| `/api/threat-intel/sync` | POST | 手动触发威胁情报同步 / Trigger threat-intel sync |
| `/metrics` | GET | Prometheus 指标 / Prometheus metrics |

> 受保护端点默认允许匿名访问；设置 `api_token` 后需在请求头携带 `Authorization: Bearer <token>`。  
> Protected endpoints are anonymous by default; set `api_token` and send `Authorization: Bearer <token>`.

---

## 测试 / Testing

### 单元测试 / Unit tests

```bash
cargo test --workspace --exclude eshield-ebpf
```

### 集成测试 / Integration tests

需要 root，会在 network namespace 中创建 veth 对并运行多项场景测试：

```bash
sudo bash ./tests/netns_test.sh
```

覆盖：黑名单、TCP RST 回包、速率限制、SYN Flood、L7 指纹、HTTP WAF、JS Challenge、服务停止后恢复、SIGHUP 热加载、自适应阈值、GeoIP/ASN、威胁情报。

Covers blacklist, TCP RST on drop, rate limiting, SYN flood, L7 fingerprint, HTTP WAF, JS Challenge, service-stop restoration, SIGHUP reload, adaptive threshold, GeoIP/ASN, and threat intel.

### 基准测试 / Benchmarks

```bash
cargo build --package eshield --target x86_64-unknown-linux-musl --release
sudo bash scripts/benchmark.sh
```

可通过环境变量调整：

```bash
PACKETS=500000 INTERVAL=u1 sudo -E bash scripts/benchmark.sh
```

详见 [docs/benchmark.md](docs/benchmark.md)。

---

## 项目结构 / Project Structure

```text
.
├── eshield/            # 用户态控制面 / Userspace control plane
│   ├── src/main.rs     # CLI + 守护进程启动
│   ├── src/control.rs  # eBPF Map 操作 / 运行时策略 / SIGHUP 重载
│   ├── src/web.rs      # REST API + Web Dashboard
│   ├── src/dashboard.html
│   ├── src/tui.rs      # TUI 仪表盘
│   ├── src/config.rs   # 配置模型与校验
│   ├── src/store.rs    # redb 持久化
│   ├── src/adaptive.rs # 自适应阈值引擎
│   ├── src/audit.rs    # 审计日志
│   ├── src/geoip.rs    # GeoIP/ASN 加载
│   ├── src/threat_intel.rs
│   └── ...
├── eshield-ebpf/       # 内核态 eBPF/XDP 数据面 / Kernel eBPF/XDP data plane
├── eshield-common/     # 内核/用户态共享结构体 / Shared kernel/userspace types
├── xtask/              # 构建任务封装 / Build task helpers
├── scripts/            # install.sh / uninstall.sh / benchmark.sh
├── tests/              # 集成测试脚本 / Integration tests
├── docs/               # 架构、部署、开发环境、API、基准测试文档
├── packaging/          # systemd 服务、deb/rpm 配置、示例配置
├── README.md
└── LICENSE
```

---

## 定位与限制 / Positioning & Limitations

- **主机级 CC 防御盾**：面向“带宽没满、但 CPU/连接数被耗尽”的 CC / 慢速攻击场景。  
  **Host-level CC defense shield**: targets CC / slow attacks that exhaust CPU or connections rather than raw bandwidth.
- **不是 DDoS 银弹**：T 级带宽耗尽型攻击需要云厂商黑洞/清洗，eShield 无法突破物理网络天花板。  
  **Not a DDoS silver bullet**: Terabit-scale bandwidth floods require upstream cloud mitigation; eShield cannot exceed physical network limits.
- **SYN Cookie 代理**：当前仅支持 IPv4 TCP；启用后所有 SYN 都会受到 Cookie 挑战。  
  **SYN Cookie proxy**: currently IPv4 TCP only; all SYNs are challenged when enabled.
- **WAF 与 L7 扫描**：仅检查 TCP 首包，适合首包即携带完整请求头的场景；不支持 TCP 分段重组。  
  **WAF & L7 scan**: inspect only the first TCP packet; TCP reassembly is not supported.
- **Windows**：无法直接编译或运行，请使用 Linux 环境。  
  **Windows**: cannot build or run directly; use a Linux environment.
- **防护项目**：当前为控制面配置分组，尚未在 eBPF 数据面按项目逐包匹配。  
  **Protection projects**: currently a control-plane policy grouping; per-packet enforcement in eBPF is not yet enabled.

---

## 文档 / Documentation

- [架构设计 / Architecture](docs/architecture.md)
- [部署指南 / Deployment](docs/deployment.md)
- [开发环境 / Development environment](docs/dev-linux.md)
- [运维指南 / Operations](docs/operations.md)
- [API 文档 / API](docs/api.md)
- [基准测试 / Benchmarks](docs/benchmark.md)

---

## License

Apache-2.0

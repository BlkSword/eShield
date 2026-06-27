# eShield

基于 **eBPF/XDP** 的**主机级 CC 防御盾**。单二进制、内核态过滤、一键安装。

> 当 Cloudflare 太贵、iptables 太慢、商业 WAF 太重时，eShield 是独立开发者与小站长能负担得起的最后一道主机防线——在 XDP 层把 CC 流量挡在内核协议栈之外。

[![CI](https://github.com/eshield/eshield/actions/workflows/ci.yml/badge.svg)](https://github.com/eshield/eshield/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 目录

- [核心特性](#核心特性)
- [架构概览](#架构概览)
- [快速开始](#快速开始)
  - [环境要求](#环境要求)
  - [一键安装](#一键安装)
  - [从源码构建](#从源码构建)
- [配置与使用](#配置与使用)
  - [CLI 子命令](#cli-子命令)
  - [配置文件](#配置文件)
  - [热加载](#热加载)
- [观测面](#观测面)
- [测试](#测试)
- [项目结构](#项目结构)
- [定位与限制](#定位与限制)
- [文档](#文档)
- [License](#license)

---

## 核心特性

| 能力 | 说明 |
|---|---|
| **eBPF/XDP 包过滤** | 流量在进入内核协议栈前被处理，开销远低于 iptables/nftables。 |
| **CIDR 白名单** | 基于 LPM Trie，支持 IPv4/IPv6 CIDR（如 `10.0.0.0/8`、`2001:db8::/32`），优先放行可信流量。 |
| **动态黑名单** | 命中防御策略的源 IP 自动加入 LRU Hash，到期自动解封。 |
| **Per-IP 速率限制** | 指数衰减滑动窗口，灵敏识别突发 CC 流量，避免误杀正常用户。 |
| **UDP / ICMP Flood 防护** | 对 UDP、ICMP/ICMPv6 无连接流量做 per-IP 速率抑制。 |
| **端口/协议 ACL** | 基于协议与目的端口的规则引擎，支持 allow/drop。 |
| **SYN Cookie 代理** | SYN Flood 场景下用 SYN-ACK Cookie 挑战替换原始 SYN，合法 ACK 验证后放行；支持 MSS 选项协商。 |
| **HTTP WAF 规则引擎** | 基于 TCP 首包解析，支持 method / path_prefix / host / user_agent / body_prefix 多维度匹配，支持 drop / log / challenge 动作。 |
| **JS Challenge 模式** | WAF action 为 `challenge` 时拦截请求，客户端完成 `/challenge` 页面 JS 验证后自动加入临时白名单。 |
| **GeoIP/ASN 过滤** | 基于 LPM Trie CIDR 匹配，支持自定义国家/ASN CSV 或 MaxMind MMDB，按国家/ASN 批量拦截或放行。 |
| **威胁情报联动** | 定时同步 AbuseIPDB、CINS 或自定义 URL 的 feed，自动拦截已知恶意 IP。 |
| **L7 轻量指纹扫描** | 检查 TCP 载荷前 64 字节，匹配特征即 DROP（如恶意 UA、扫描指纹）。 |
| **自适应阈值引擎** | 重复触发规则的 IP 自动提升为更长时间的封禁。 |
| **实时控制** | REST API + 中文 Web Dashboard + CLI，可实时封禁/解封 IP、编辑 WAF/端口 ACL/L7 指纹规则、更新速率限制与开关。 |
| **配置热加载** | 通过 `SIGHUP` 或 `systemctl reload` 重新加载配置文件，无需重启服务。 |
| **认证/审计/持久化** | 可选 Bearer Token；审计日志；动态规则持久化到 redb。 |
| **可观测性** | 中文 Web Dashboard（侧边栏导航、暗黑/亮色主题、实时流量趋势图、IP 情报抽屉）、Prometheus `/metrics`、健康检查、告警 Webhook、JSON/文本日志、中文 TUI 仪表盘。 |
| **单二进制静态链接** | 基于 musl 静态编译，发布时仅需一个 `eshield` 可执行文件。 |

---

## 架构概览

```text
┌─────────────────────────────────────────────────────────┐
│ 管理面 (Management Plane)                               │
│ Web Dashboard (axum) │ TUI (ratatui) │ CLI             │
└──────────────────────────────┬──────────────────────────┘
                               │ REST API / Config Watch
┌──────────────────────────────▼──────────────────────────┐
│ 控制面 (Control Plane) — Rust 用户态                     │
│ 配置管理 │ 事件消费 │ 指标聚合 │ 自适应阈值引擎          │
└──────────────────────────────┬──────────────────────────┘
                               │ BPF Maps / Ring Buffer
┌──────────────────────────────▼──────────────────────────┐
│ 数据面 (Data Plane) — eBPF/XDP 内核态                    │
│ 包解析 → 白名单 → Challenge 临时白名单 → 端口 ACL → GeoIP → UDP/ICMP Flood → 速率限制 → SYN Proxy → WAF → L7 扫描 → 决策 │
└─────────────────────────────────────────────────────────┘
```

详细设计见 [docs/architecture.md](docs/architecture.md)。

---

## 快速开始

### 环境要求

- **Linux**（物理机 / 虚拟机 / 云主机 / WSL2）
- Linux 内核 >= **5.10**，且启用 **BTF**：
  ```bash
  ls /sys/kernel/btf/vmlinux
  ```
- root 权限或以下 capability：`CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_PERFMON`、`CAP_IPC_LOCK`
- Rust >= 1.70（nightly + bpf target）
- LLVM / clang（Aya 编译 eBPF 需要）

> ⚠️ **Windows 开发者注意**：Aya 用户态库依赖 Linux 特有 API，因此**无法在 Windows 上直接编译或运行**。请在 WSL2 / 虚拟机 / 云主机上进行构建和测试。代码可以在 Windows 上编辑，但构建与运行必须在 Linux 环境。

### 一键安装（从 Release）

```bash
curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo bash
```

指定版本：

```bash
VERSION=0.2.0 curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo VERSION=0.2.0 bash
```

### 从源码构建并安装

```bash
sudo bash scripts/install.sh --build
```

这会：

1. 使用 nightly 工具链编译 eBPF 程序
2. 使用 musl target 静态编译用户态二进制
3. 将 `eshield` 安装到 `/usr/local/bin`
4. 创建默认配置 `/etc/eshield/config.toml`
5. 安装并启用 systemd 服务

### 服务管理

```bash
sudo systemctl status eshield
sudo systemctl start eshield
sudo systemctl stop eshield
sudo systemctl restart eshield
sudo systemctl reload eshield   # SIGHUP 热加载配置
sudo journalctl -u eshield -f
```

---

## 配置与使用

### CLI 子命令

```bash
# 启动守护进程
sudo eshield start --config /etc/eshield/config.toml

# 查看状态
eshield status

# 实时封禁 IP（0 秒表示永久）
eshield block 192.0.2.1 --duration 300

# 实时解封 IP
eshield unblock 192.0.2.1

# 重新加载配置文件
eshield reload

# 启动独立 TUI 仪表盘（连接本地 Web API）
eshield tui

# 指定远程 API 端点
eshield status --endpoint http://eshield-host:8443
eshield block 192.0.2.1 --endpoint http://eshield-host:8443
```

### 配置文件

默认路径 `/etc/eshield/config.toml`：

```toml
interface = "eth0"          # 要挂载 XDP 的网卡
log_level = "info"          # trace/debug/info/warn/error
log_json = false            # 是否以 JSON 格式输出日志
ebpf_log_enabled = false    # 是否启用 eBPF 内核调试日志（AYA_LOGS）
whitelist = ["127.0.0.1/32", "10.0.0.0/8"]
blacklist = ["192.0.2.1"]
web_bind = "0.0.0.0:8443"   # Web / Prometheus / API 监听地址
# api_token = "changeme"    # 可选：启用 API 认证
store_path = "/var/lib/eshield/rules.redb"  # 动态规则持久化

[rate_limit]
enabled = true
threshold = 200             # 每个 tick 内允许的最大包数
tick_ms = 100               # 计数窗口
decay_num = 7
decay_den = 8               # 指数衰减因子 7/8
block_duration_s = 300      # 触发后封禁时长

[syn_proxy]
enabled = false             # 开启后会用 SYN Cookie 挑战替代原始 SYN

[l7_scan]
enabled = false
patterns = [
    { pattern = "ATTACKER" },
]

[adaptive]
enabled = true
threshold = 10              # 指定窗口内触发多少次后自动封禁
window_s = 5
block_duration_s = 300

[waf]
enabled = false
rules = [
    { name = "block-admin", enabled = true, priority = 1, action = "drop", match = { method = "GET", path_prefix = "/admin" } },
    { name = "challenge-secret", enabled = true, priority = 2, action = "challenge", match = { method = "GET", path_prefix = "/secret" } },
]

[challenge]
enabled = true
mode = "js"
ttl_s = 3600

[geoip]
enabled = false
country_blocks_csv = "/etc/eshield/geoip_country.csv"
block_countries = ["XX"]
default_action = "pass"

[threat_intel]
enabled = false
# [[threat_intel.feeds]]
# name = "abuseipdb"
# url = "https://api.abuseipdb.com/api/v2/blacklist"
# interval_s = 3600
# action = "drop"
# confidence = 80
```

> **注意**：`syn_proxy.enabled = true` 时，原始 SYN 会被改写为 SYN-ACK 并丢弃，合法 ACK 验证后才会放行。v0.2.0 已实现 SYN Cookie 代理的 MSS 选项协商，可支持正常 TCP 业务长期开启；但仍建议仅在 SYN Flood 场景或需要挑战/代理能力时启用。

### 热加载

修改 `/etc/eshield/config.toml` 后：

```bash
sudo systemctl reload eshield
# 或
sudo kill -HUP $(pidof eshield)
```

日志中会出现 `config reloaded successfully`，无需中断现有连接。

---

## 观测面

### Web Dashboard（中文）

启动后访问：

```
http://<host>:8443/
```

中文界面，展示实时包统计、按规则维度命中数、TOP 攻击源、审计日志，并提供实时控制表单：

- 封禁 / 解封 IPv4/IPv6
- 放行 / 移除 IPv4/IPv6 CIDR
- 启用/禁用速率限制、SYN Cookie 代理、L7 指纹扫描、UDP/ICMP Flood 防护、WAF、GeoIP
- 实时开关 eBPF 内核调试日志
- 调整速率限制阈值与 tick
- 输入 API Token（启用认证时）
- 一键重载配置文件
- 展示 WAF 规则、GeoIP 配置、威胁情报 feed、黑白名单策略

### Prometheus 指标

```
http://<host>:8443/metrics
```

暴露多维计数器，可直接被 Prometheus 抓取：

- `eshield_dropped_total`
- `eshield_blacklist_blocked_total`
- `eshield_rate_limited_total`
- `eshield_syn_flood_blocked_total`
- `eshield_l7_blocked_total`
- `eshield_adaptive_blocked_total`
- `eshield_waf_blocked_total`
- `eshield_geoip_blocked_total`
- `eshield_challenge_issued_total`
- `eshield_source_dropped_total{ip="..."}`

### JSON 统计接口

```bash
curl http://<host>:8443/api/stats | jq
```

### TUI 仪表盘（中文）

```bash
eshield tui
```

中文界面，显示总丢弃、各规则拦截数、TOP 攻击源；按 `q` 退出，每 500ms 刷新一次。

---

## 测试

### 单元测试

```bash
cargo test --workspace --exclude eshield-ebpf
```

### 集成测试

需要 root，会在 netns 中创建 veth 对并运行 7 项场景测试：

```bash
sudo bash ./tests/netns_test.sh
```

覆盖：黑名单、速率限制、SYN Flood、L7 指纹、HTTP WAF、JS Challenge、GeoIP/ASN、威胁情报、SIGHUP 热加载、自适应阈值、停止后恢复。

### 基准测试

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

## 项目结构

```text
.
├── eshield/            # 用户态控制面（Rust + Tokio + axum + ratatui）
│   ├── src/control.rs  # 控制面：eBPF Map 操作 / 运行时策略 / SIGHUP 重载
│   ├── src/web.rs      # REST API + 中文 Web Dashboard
│   ├── src/dashboard.html
│   ├── src/tui.rs      # 中文 TUI 仪表盘
│   └── src/main.rs     # CLI + 守护进程启动
├── eshield-ebpf/       # 内核态 eBPF/XDP 数据面（Rust + Aya）
├── eshield-common/     # 内核/用户态共享结构体与规则 ID
├── xtask/              # 构建任务封装（cargo xtask build/run/test）
├── scripts/            # install.sh / uninstall.sh / benchmark.sh / build-release.sh
├── tests/              # 集成测试脚本
├── docs/               # 架构、部署、基准测试、开发环境文档
├── README.md
└── ROADMAP.md
```

---

## 定位与限制

- **主机级 CC 防御盾**：面向“带宽没满、但 CPU/连接数被耗尽”的 CC / 慢速攻击场景。
- **不是 DDoS 银弹**：T 级带宽耗尽型攻击需要云厂商黑洞/清洗，eShield 无法突破物理网络天花板。
- **SYN Proxy 当前实现**：提供 SYN Cookie 挑战与 ACK 验证，但不维护完整后端连接状态；正常 TCP 业务请勿长期开启。
- **IPv6**：已支持 IPv6 数据面与配置，部分部署文档示例仍以 IPv4 为主。

---

## 文档

- [架构设计](docs/architecture.md)
- [部署指南](docs/deployment.md)
- [开发环境](docs/dev-linux.md)
- [基准测试](docs/benchmark.md)

---

## License

Apache-2.0

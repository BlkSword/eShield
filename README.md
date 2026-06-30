# eShield

基于 **eBPF/XDP** 的主机级 CC / L3-L4 网络防御盾。

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[English README](README_EN.md)

---

## 目录

- [项目简介](#项目简介)
- [性能与能力优势](#性能与能力优势)
  - [性能](#性能)
  - [攻击者需要耗费的资源](#攻击者需要耗费的资源)
- [核心特性](#核心特性)
- [架构概览](#架构概览)
- [快速开始](#快速开始)
- [配置与使用](#配置与使用)
- [观测面](#观测面)
- [API 概览](#api-概览)
- [测试](#测试)
- [项目结构](#项目结构)
- [定位与限制](#定位与限制)
- [文档](#文档)
- [License](#license)

---

## 项目简介

eShield 在 Linux 内核 XDP 钩子上运行一个由 Rust/Aya 编写的 eBPF 程序，将恶意流量在进入内核网络协议栈之前拦截。控制面使用 Rust + Tokio + axum 提供 Web Dashboard、REST API、CLI、TUI、审计日志、持久化与告警能力。

与 iptables/nftables 等传统方案相比，eShield 的决策点位于网卡驱动层，具备更低的延迟、更高的包处理吞吐，以及对 CC / 慢速连接耗尽型攻击更精准的识别能力。

---

## 性能与能力优势

### 性能

- **内核态包处理**：过滤逻辑直接在 eBPF/XDP 中运行，不经过用户态网络栈，无上下文切换、无数据拷贝。
- **微秒级延迟**：对正常流量仅增加一次 eBPF Map 查表和规则匹配开销，典型延迟增加小于 1 µs。
- **高吞吐**：在 veth 单核测试环境中，XDP PASS 路径可达约 **24 万 pps**，DROP 路径因提前丢弃、避免协议栈处理而接近甚至低于基线；物理网卡配合多队列/RSS 可扩展至数百万 pps。
- **低开销**：eBPF 程序为 JIT 编译成本地机器码，CPU 占用随流量线性增长但斜率极低；命中黑名单/ACL 的包可被硬件级早 drop。
- **单二进制静态链接**：musl 静态编译，仅需一个 `eshield` 可执行文件，无额外运行时依赖。

> 详细基准测试方法见 [docs/benchmark.md](docs/benchmark.md)。

### 攻击者需要耗费的资源

由于 eShield 在流量最早期进行拦截，攻击方要产生有效压力必须付出真实成本：

- **真实带宽**：每一个被丢弃的包都会实际占用攻击者的出口带宽；速率限制和黑名单会在命中瞬间丢弃，不会消耗防御方后端带宽。
- **真实源 IP**：黑名单、GeoIP、威胁情报、自适应阈值均基于源 IP 累计。攻击者需要大量分布式、可轮换的真实 IPv4/IPv6 地址才能维持攻击。
- **协议栈完整交互**：SYN Cookie 代理要求每个伪造源都必须完成完整的三次握手；JS Challenge 要求浏览器执行 JavaScript 并携带正确答案；WAF 规则会放行仅匹配合法请求特征的流量。绕过这些机制需要真实的 TCP/IP 协议栈、浏览器环境或足够的计算资源。
- **持续人力与计算**：自适应引擎会自动对重复触发规则的源提升封禁时长，攻击者必须不断变换特征、IP 段和攻击模式，维护成本显著高于防御方。

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
| HTTP WAF 规则引擎 | 解析 TCP 首包，支持 method / path_prefix / host / user_agent / body_prefix 匹配。 |
| JS Challenge | WAF `challenge` 动作拦截请求，完成 `/challenge` 验证后加入临时白名单。 |
| GeoIP / ASN 过滤 | 基于自定义 CSV CIDR 列表按国家或 ASN 放行/封禁。 |
| 威胁情报联动 | 定时同步自定义 URL feed，自动拦截已知恶意 IP。 |
| L7 轻量指纹扫描 | 检查 TCP 载荷前 64 字节，匹配特征即 DROP。 |
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
│ Flood → L7 扫描 → WAF → 速率限制 → 黑名单 → 决策             │
└─────────────────────────────────────────────────────────────┘
```

详细设计见 [docs/architecture.md](docs/architecture.md)。

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

### 一键安装

```bash
curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo bash
```

指定版本：

```bash
VERSION=0.2.0 curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo VERSION=0.2.0 bash
```

### 从源码构建

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

默认路径 `/etc/eshield/config.toml`：

```toml
# 要挂载 XDP 的网卡
interface = "eth0"

log_level = "info"          # trace/debug/info/warn/error
log_json = false            # 是否以 JSON 格式输出日志
ebpf_log_enabled = false    # eBPF 内核调试日志开关

udp_flood_enabled = false   # UDP Flood 防护
icmp_flood_enabled = false  # ICMP/ICMPv6 Flood 防护
tcp_reset_on_drop = false   # 对丢弃的 TCP 连接回复 RST

web_bind = "0.0.0.0:8443"   # Web / API / Prometheus 监听地址
# api_token = "changeme"    # 可选 API 认证

store_path = "/var/lib/eshield/rules.redb"  # 动态规则持久化

# 告警 Webhook（可选）
# alert_webhook_url = "https://hooks.example.com/eshield"
alert_webhook_type = "generic"   # generic / slack / dingtalk / wecom
alert_threshold_dps = 1000
alert_cooldown_s = 60

# 白名单 CIDR
whitelist = ["127.0.0.1/32", "10.0.0.0/8"]

# 黑名单 IP/CIDR（启动时加载，永久封禁）
blacklist = ["192.0.2.1"]

[rate_limit]
enabled = true
threshold = 200             # 每个 tick 允许的最大包数
tick_ms = 100               # 计数窗口
decay_num = 7
decay_den = 8               # 指数衰减因子
block_duration_s = 300      # 触发后封禁时长

[syn_proxy]
enabled = false             # SYN Cookie 代理

[l7_scan]
enabled = false
patterns = [
    { pattern = "ATTACKER" },
]

[adaptive]
enabled = true
threshold = 10              # 窗口内触发次数
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
ttl_s = 3600                # 临时白名单有效期

[geoip]
enabled = false
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

# 端口/协议 ACL
# [[port_acl]]
# protocol = "tcp"
# dport = "22"
# action = "allow"

# 防护项目（控制面分组）
# [[protection_projects]]
# name = "web-service"
# description = "Protect public HTTP service"
# protocol = "tcp"
# dport = "80"
# target_ips = ["10.0.0.10"]
# enabled_modules = ["rate_limit", "waf", "challenge"]
# action = "defend"   # pass / drop / defend
```

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

### Prometheus 指标

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

### JSON 统计接口

```bash
curl -H "Authorization: Bearer <token>" http://<host>:8443/api/stats | jq
```

### TUI 仪表盘

```bash
eshield tui
```

中文界面，显示总丢弃、各规则拦截数、TOP 攻击源；按 `q` 退出。

### 审计日志

- `GET /api/audit` 查询审计事件，支持 `limit`、`ip`、`action`、`from`、`to` 过滤。
- `GET /api/audit/stream` SSE 实时推送审计事件。

---

## API 概览

| 端点 | 方法 | 说明 |
|---|---|---|
| `/healthz` | GET | 健康检查 |
| `/ready` | GET | 就绪检查 |
| `/login` | GET | 控制台登录页 |
| `/challenge` | GET | JS Challenge 页面 |
| `/blocked` | GET | 403 封禁示例页 |
| `/api/challenge/pass` | POST | 提交 challenge 答案 |
| `/api/auth/login` | POST | 控制台登录验证 |
| `/api/auth/check` | GET | 登录状态检查 |
| `/api/auth/reset-token` | POST | 重置访问令牌（外部需认证，本机 CLI 可直接调用） |
| `/` | GET | Web Dashboard |
| `/api/stats` | GET | 运行统计 |
| `/api/config` | GET, PATCH | 读取/修改运行时配置 |
| `/api/config/reload` | POST | 从文件重新加载配置 |
| `/api/protection-modules` | GET | 防护模块列表与状态 |
| `/api/blacklist` | POST, DELETE | 封禁/解封 IP |
| `/api/whitelist` | POST, DELETE | 添加/移除 CIDR 白名单 |
| `/api/audit` | GET | 审计日志 |
| `/api/audit/stream` | GET | 审计日志 SSE |
| `/api/metrics/series` | GET | 时序指标 |
| `/api/metrics/attacker-series` | GET | 单 IP 时序 |
| `/api/waf/rules` | GET, POST | WAF 规则 CRUD |
| `/api/waf/rules/reorder` | POST | WAF 规则排序 |
| `/api/port-acl` | GET, POST | 端口 ACL |
| `/api/protection-projects` | GET, POST | 防护项目 |
| `/api/l7-patterns` | GET, POST | L7 指纹 |
| `/api/geoip/reload` | POST | 重新加载 GeoIP CSV |
| `/api/threat-intel/sync` | POST | 手动触发威胁情报同步 |
| `/metrics` | GET | Prometheus 指标 |

> 外部访问受保护端点时，若设置了 `api_token`，需在请求头携带 `Authorization: Bearer <token>`；本机 CLI 自动跳过认证。

---

## 测试

### 单元测试

```bash
cargo test --workspace --exclude eshield-ebpf
```

### 集成测试

需要 root，会在 network namespace 中创建 veth 对并运行多项场景测试：

```bash
sudo bash ./tests/netns_test.sh
```

覆盖：黑名单、TCP RST 回包、速率限制、SYN Flood、L7 指纹、HTTP WAF、JS Challenge、服务停止后恢复、SIGHUP 热加载、自适应阈值、GeoIP/ASN、威胁情报。

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
├── eshield/            # 用户态控制面
│   ├── src/main.rs     # CLI + 守护进程启动
│   ├── src/control.rs  # eBPF Map 操作 / 运行时策略 / SIGHUP 重载
│   ├── src/web.rs      # REST API + Web Dashboard
│   ├── src/dashboard.html
│   ├── src/login.html
│   ├── src/challenge.html
│   ├── src/blocked.html
│   ├── src/tui.rs      # TUI 仪表盘
│   ├── src/config.rs   # 配置模型与校验
│   ├── src/store.rs    # redb 持久化
│   ├── src/adaptive.rs # 自适应阈值引擎
│   ├── src/audit.rs    # 审计日志
│   ├── src/geoip.rs    # GeoIP/ASN 加载
│   ├── src/threat_intel.rs
│   └── ...
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

- **主机级 CC 防御盾**：面向“带宽没满、但 CPU/连接数被耗尽”的 CC / 慢速攻击场景。
- **不是 DDoS 银弹**：T 级带宽耗尽型攻击需要云厂商黑洞/清洗，eShield 无法突破物理网络天花板。
- **SYN Cookie 代理**：当前仅支持 IPv4 TCP；启用后所有 SYN 都会受到 Cookie 挑战。
- **WAF 与 L7 扫描**：仅检查 TCP 首包，适合首包即携带完整请求头的场景；不支持 TCP 分段重组。
- **Windows**：无法直接编译或运行，请使用 Linux 环境。
- **防护项目**：当前为控制面配置分组，尚未在 eBPF 数据面按项目逐包匹配。

---

## 文档

- [架构设计](docs/architecture.md)
- [部署指南](docs/deployment.md)
- [开发环境](docs/dev-linux.md)
- [运维指南](docs/operations.md)
- [API 文档](docs/api.md)
- [基准测试](docs/benchmark.md)

---

## License

Apache-2.0

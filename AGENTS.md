# eShield — AI Agent 项目指南

> 本文件面向不了解 eShield 的 AI 编码助手。项目的主要文档和代码注释使用**中文**，因此本指南也使用中文撰写；代码、命令、文件路径和标识符保持原样。

---

## 1. 项目概述

**eShield**（版本 `0.4.5`）是一个基于 **eBPF/XDP** 的主机级 L3-L4 网络清洗盾，专注防御 SYN/UDP/ICMP Flood、CC、网络层扫描等攻击。

- **数据面**：用 Rust/Aya 编写的 eBPF 程序挂载在 Linux XDP 钩子上，在包进入内核网络协议栈之前完成过滤/丢弃/挑战。
- **控制面**：Rust + Tokio + axum，提供 REST API、中文 Web Dashboard、CLI、TUI、审计日志、持久化与告警。
- **目标产物**：单二进制静态链接（musl），只需要 `eshield` 一个可执行文件即可运行。

> **重要限制**：eShield 是主机级清洗盾，不能突破物理带宽上限；T 级带宽耗尽型攻击需要上游云厂商清洗。SYN Cookie 代理目前仅支持 IPv4 TCP；L7 扫描仅检查 TCP 首包；防护项目当前只在控制面分组，未在 eBPF 数据面逐包匹配。

---

## 2. 技术栈与运行环境

### 2.1 开发/运行环境

- **操作系统**：Linux（内核 >= 5.10），必须启用 **BTF**：
  ```bash
  ls /sys/kernel/btf/vmlinux
  ```
- **权限**：root，或具备以下 capability：
  `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_PERFMON`、`CAP_IPC_LOCK`
- **Rust**：
  - stable：用于用户态（`x86_64-unknown-linux-musl`）。
  - nightly：用于 eBPF（`bpfel-unknown-none`，需要 `rust-src`）。
- **构建工具**：LLVM / clang、`bpf-linker`。
- **注意**：Aya 用户态依赖 Linux API，**无法在 Windows 上直接编译或运行**；代码编辑可以在 Windows 完成，构建和测试必须在 WSL2 / 虚拟机 / 远程 Linux 上执行。

### 2.2 核心技术栈

| 层面 | 技术 |
|---|---|
| 数据面 | Rust + Aya (`aya-ebpf`, `aya-log-ebpf`)，eBPF/XDP |
| 控制面 | Rust + Tokio + axum + clap |
| 持久化 | redb（嵌入式 KV） |
| 终端 UI | ratatui + crossterm |
| 网络客户端 | reqwest（rustls-tls） |
| 序列化 | serde / serde_json / toml |
| 日志 | tracing + tracing-subscriber |

---

## 3. 代码组织

这是一个 Cargo Workspace，根目录 `Cargo.toml` 定义了 5 个成员：

```text
.
├── eshield/            # 用户态控制面（主二进制）
├── eshield-common/     # 内核态/用户态共享类型
├── eshield-ebpf/       # eBPF/XDP 数据面
├── eshield-hub/        # 分布式策略聚合 Hub
└── xtask/              # 构建任务封装
```

### 3.1 `eshield`（用户态控制面）

主二进制入口：`eshield/src/main.rs`，提供 CLI 子命令和守护进程生命周期管理。

主要模块：

- `main.rs`：CLI（`start` / `status` / `block` / `unblock` / `reload` / `check` / `tui` / `reset-token`）与守护进程启动流程。
- `config.rs`：`/etc/eshield/config.toml` 的解析、默认值与校验。
- `control.rs`：封装所有 eBPF Map 操作、配置热加载、持久化规则恢复。
- `state.rs`：内存中的统计状态（PPS/DPS、Top 攻击源、Trust Score 分布等）。
- `event_consumer.rs`：消费 eBPF Ring Buffer 事件。
- `web.rs`：axum HTTP 服务（控制台静态资源、REST API、Prometheus `/metrics`、审计 SSE）。
- `auth.rs`：Bearer Token 认证；本机 `127.0.0.1/::1` 自动跳过校验。
- `audit.rs`：审计日志后端（内存 / JSON Lines 文件）。
- `store.rs`：基于 redb 的规则持久化。
- `adaptive.rs`：自适应阈值引擎，重复触发自动提升封禁时长。
- `danger.rs`：系统危险信号监测（CPU/内存/DPS 异常时调整全局防御等级）。
- `geoip.rs`：GeoIP / ASN CIDR 列表加载。
- `threat_intel.rs`：自定义威胁情报 feed 同步。
- `hub_client.rs`：分布式 Hub 同步客户端。
- `blacklist_sync.rs`：将 `BLACKLIST` Map 中的动态命中同步到 redb，供 Hub 上报。
- `alert.rs`：告警 Webhook。
- `tui.rs`：终端 Dashboard。
- `health.rs`、`timeseries.rs`、`ip.rs`、`time.rs`、`login_limiter.rs`：辅助模块。

Web 控制台前端位于 `eshield/web/`（原生 ES modules + 模块化 CSS，无前端构建链，经 `include_str!`/`include_bytes!` 嵌入二进制）：

- `index.html`：应用骨架，`__CONFIG_JSON__` 注入运行时配置。
- `css/`：`tokens.css`（design tokens，暗/亮双主题）、`base.css`（布局/侧边栏/头部）、`components.css`（卡片/表格/表单/抽屉/Toast 等）、`pages.css`（页面级）。
- `js/`：`main.js`（入口：主题/侧边栏/SSE/快捷键/路由启动）、`api.js`（fetch 封装 + 认证）、`store.js`（状态总线）、`router.js`（hash 路由 + 页面生命周期）、`format.js`（格式化，唯一一份）、`icons.js`（SVG 图标）、`ui.js`（Toast/骨架屏/抽屉等）、`charts.js`（ECharts 主题感知助手）、`ipdrawer.js`（IP 情报抽屉，全站共享）。
- `js/pages/`：九个页面模块（overview / attacks / packets / audit / policy / rules / security / cluster / settings），每个导出 `id`/`title`/`sub`/`mount(el)→unmount`。
- 新增/删除静态文件时，必须同步 `web.rs` 中的 `STATIC_ASSETS` 表。
- 旧版单文件控制台 `eshield/src/dashboard.html` 保留在 `/legacy` 一个版本周期，随后删除。

### 3.2 `eshield-ebpf`（内核态数据面）

`#![no_std]` eBPF 程序，入口 `src/main.rs`，XDP 程序名为 `eshield`。

主要模块：

- `main.rs`：`eshield` XDP 主流程：解析 → 白名单 → 端口 ACL → GeoIP → TCP（SYN Proxy / SYN Flood）→ UDP Flood → ICMP Flood → L7 扫描 → 速率限制 → 黑名单 → 决策。
- `parser.rs`：有界读取 Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP 头部。
- `maps.rs`：BPF Maps 定义。
- `blacklist.rs`：LRU Hash 黑名单查询。
- `port_acl.rs`：端口/协议 ACL。
- `rate_limit.rs` / `rate_counter.rs`：指数衰减滑动窗口速率限制。
- `syn_cookie.rs` / `syn_flood.rs`：SYN Cookie 代理与 SYN Flood 检测。
- `udp_flood.rs` / `icmp_flood.rs`：无连接 Flood 检测。
- `l7_scan.rs`：TCP 首包指纹扫描。
- `tcp_reset.rs`：丢弃 TCP 包时回复 RST。
- `trust.rs`：IP 双向信誉评分。

### 3.3 `eshield-common`（共享类型）

- `lib.rs`：`#[repr(C)]` 的共享结构体，如 `IpKey`、`DropEvent`、`BlockEntry`、`GlobalStats`、规则 ID 常量等。
- `pure.rs`：无副作作用工具函数。

通过 `userspace` feature 启用 `aya` 与 `serde` 派生。

### 3.4 `eshield-hub`（分布式策略聚合中心）

独立二进制 `eshield-hub`。

主要模块：

- `main.rs`：命令行参数解析与服务启动。
- `api.rs`：Hub REST API（节点注册、策略推/拉、规则包下发）。
- `auth.rs` / `tls.rs`：Token 认证与 TLS 配置。
- `registry.rs`：节点注册表与超时清理。
- `store.rs`：基于 redb 的策略存储。
- `models.rs`：Hub 数据模型。
- `feed.rs`：Hub 统一下发威胁情报 feed。
- `limiter.rs`：API 速率限制。

---

## 4. 构建命令

### 4.1 安装依赖

```bash
rustup toolchain install nightly --component rust-src
rustup target add bpfel-unknown-none --toolchain nightly
rustup target add x86_64-unknown-linux-musl

# Debian/Ubuntu
sudo apt-get install -y llvm clang libelf-dev

# bpf-linker
cargo install cargo-binstall
cargo binstall bpf-linker
```

### 4.2 常用构建命令

```bash
# 仅构建 eBPF（release）
cargo xtask build-ebpf

# 构建 eBPF + 用户态静态二进制（release）
cargo xtask build

# 构建并运行（默认网卡 eth0）
cargo xtask run --iface eth0

# 完整发布产物（二进制 + eBPF + 可选 DEB/RPM）
bash scripts/build-release.sh

# 一键从源码构建并安装到本机（/usr/local/bin、/etc/eshield、systemd）
sudo bash scripts/install.sh --build
```

构建产物：

- 用户态：`target/x86_64-unknown-linux-musl/release/eshield`
- eBPF：`target/bpfel-unknown-none/release/eshield`
- 发布包：`dist/eshield-x86_64-unknown-linux-musl`、`dist/eshield.bpf.o`，以及可选的 `.deb` / `.rpm`。

---

## 5. 代码风格与静态检查

项目使用标准 Rust 风格：

```bash
# 格式化检查
cargo fmt --check

# Clippy（用户态）
cargo clippy --workspace --exclude eshield-ebpf -- -D warnings

# Clippy（eBPF，需要 nightly + bpf target）
cargo +nightly clippy --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core -- -D warnings

# xtask 一键执行 fmt + clippy + test
cargo xtask test
```

- 代码注释主要使用中文，技术术语与标识符保持英文。
- 错误处理以 `anyhow` 为主。
- eBPF 侧必须 `#![no_std]`，避免使用分配器或 panic 处理（panic handler 已在 `main.rs` 定义）。
- 共享结构体必须 `#[repr(C)]`，内核态与用户态字段对齐一致。

---

## 6. 测试命令

### 6.1 单元测试

```bash
cargo test --workspace --exclude eshield-ebpf
```

> `tests/integration_tests.rs` 当前为占位；真实集成测试通过下方 shell 脚本在 netns 中运行。

### 6.2 集成测试（需要 root + Linux）

```bash
# 单节点防御能力（netns + veth）
sudo bash tests/netns_test.sh

# 完整攻防场景
sudo bash tests/full_attack_test.sh

# 分布式 Hub-Node 端到端
sudo bash tests/hub_node_test.sh
```

这些脚本会：

1. 自动构建 eBPF 与用户态 release 二进制。
2. 创建 `eshield-server` / `eshield-client` 两个 network namespace 与一对 veth。
3. 启动 `eshield` 并验证黑名单、速率限制、SYN/UDP/ICMP Flood、L7 指纹、RST 回包、GeoIP、热加载、Hub 同步等场景。

可设置 `SKIP_BUILD=1` 跳过构建：

```bash
sudo SKIP_BUILD=1 bash tests/netns_test.sh
```

### 6.3 基准测试

```bash
cargo build --package eshield --target x86_64-unknown-linux-musl --release
sudo bash scripts/benchmark.sh
```

可调环境变量：`PACKETS`（默认 200000）、`INTERVAL`（默认 `u1`）。

---

## 7. 配置与运行

### 7.1 配置文件

默认路径：`/etc/eshield/config.toml`。
完整示例：`packaging/config.example.toml`。

关键配置段：

- `interface` / `web_bind`：XDP 挂载网卡与 Web/API 监听地址（默认 `0.0.0.0:8720`）。
- `whitelist` / `blacklist`：启动时加载的静态 CIDR 白名单与永久黑名单。
- `[rate_limit]`：per-IP 速率限制。
- `[syn_proxy]`：IPv4 SYN Cookie 代理开关。
- `udp_flood_enabled` / `icmp_flood_enabled`：无连接 Flood 防护顶层开关。
- `[l7_scan]`：TCP 首包指纹匹配。
- `[adaptive]`：重复触发自动提升封禁时长。
- `[geoip]`：国家/ASN CIDR 放行/封禁。
- `[threat_intel]`：自定义威胁情报 feed。
- `[trust_score]`：IP 双向信誉引擎（v0.4.0）。
- `[danger_signal]`：系统危险信号监测（v0.4.0）。
- `[port_acl]`：端口/协议级 allow/drop 规则。
- `[protection_projects]`：控制面策略分组。
- `[hub]`：分布式 Hub 同步配置（v0.4.2）。
- `[packet_log]`：采样包日志（v0.4.2）。

### 7.2 CLI 子命令

```bash
# 启动守护进程
sudo eshield start --config /etc/eshield/config.toml

# 查看状态（本机免 token）
eshield status

# 实时封禁/解封 IP（0 秒表示永久）
eshield block 192.0.2.1 --duration 300
eshield unblock 192.0.2.1

# 重新加载配置
eshield reload

# 校验配置
eshield check --config /etc/eshield/config.toml

# 启动 TUI
eshield tui

# 重置 Web 控制台 Token
eshield reset-token
```

### 7.3 热加载

修改配置后无需重启：

```bash
sudo systemctl reload eshield
# 或
sudo kill -HUP $(pidof eshield)
```

### 7.4 Web Dashboard 与 API

- Dashboard：`http://<host>:8720/`
- Prometheus 指标：`http://<host>:8720/metrics`
- REST API：详见 `docs/api.md`
- 审计 SSE：`GET /api/audit/stream`

认证：未设置 `api_token` 时外部访问匿名；设置后需要在请求头携带 `Authorization: Bearer <token>`。本机 CLI（`127.0.0.1/::1`）自动跳过校验。

---

## 8. 部署方式

### 8.1 systemd

`packaging/eshield.service` 配置了最小权限运行：

```bash
sudo systemctl enable --now eshield
sudo systemctl reload eshield   # SIGHUP 热加载
sudo journalctl -u eshield -f
```

默认持久化路径：`/var/lib/eshield/rules.redb`；审计日志路径：`/var/log/eshield/audit.log`。

### 8.2 容器

```bash
docker run -d --name eshield \
  --cap-add BPF --cap-add NET_ADMIN --cap-add NET_RAW \
  --cap-add PERFMON --cap-add IPC_LOCK \
  -v /etc/eshield/config.toml:/etc/eshield/config.toml:ro \
  -p 8720:8720 \
  ghcr.io/eshield/eshield:v0.4.2
```

### 8.3 分布式 Hub

启动 Hub：

```bash
eshield-hub --bind 0.0.0.0:9930 --token "your-hub-token"
```

节点配置示例：

```toml
[hub]
enabled = true
urls = ["https://hub.example.com:9930"]
node_name = "web-tier-01"
token = "your-hub-token"
sync_pull_interval_s = 10
sync_push_interval_s = 5
sync_rules_enabled = true
```

生产环境强烈建议在 Hub 前使用 nginx/Caddy 做 TLS termination。

---

## 9. 安全注意事项

- **必须 root 或高权限 capability**：加载 XDP/eBPF 程序需要 `CAP_BPF` / `CAP_NET_ADMIN` 等，无法以普通用户运行。
- **Token 管理**：建议显式设置 `api_token`；若未设置，系统会生成随机 Token 并仅在日志中输出前缀，完整 Token 需在 Dashboard 设置页查看。
- **审计与持久化**：动态规则写入 redb（`store_path`），审计日志可开启文件后端；确保这些目录的权限正确，避免敏感信息泄露。
- **威胁情报**：feed URL 通过 `reqwest` + `rustls-tls` 拉取，但仍应只使用可信来源。
- **Hub 通信**：节点与 Hub 之间使用共享 Bearer Token；生产环境务必启用 TLS，并确保 `node_name` 在集群内唯一，避免策略回环。
- **持久化策略回环规避**：`RuleStore` 加载持久化规则时会跳过 `BLACKLIST` reason，防止旧动态黑名单在配置变更后覆盖新配置。
- **SYN Cookie 密钥**：启动时随机初始化，并每分钟轮换一次。

---

## 10. 已知约束与边界

- **Windows**：无法直接编译或运行，请在 Linux/WSL2/VM 中构建测试。
- **SYN Cookie 代理**：仅 IPv4 TCP；启用后所有 SYN 都会受到 Cookie 挑战。
- **L7 扫描**：仅检查 TCP 首包前若干字节，不支持 TCP 分段重组，也不防御 HTTP Flood / CC / 慢速攻击。
- **防护项目**：当前是控制面策略分组，受 XDP verifier 512 字节组合栈限制，尚未在 eBPF 数据面按项目逐包匹配；全局防御模块仍生效。
- **XDP 挂载**：优先 `DRV_MODE`（native），失败自动回退到 `SKB_MODE`（generic）。
- **eBPF 构建**：debug 构建因 `overflow-checks` 与未内联代码容易导致 verifier/bpf-linker 失败，因此工作空间默认 `opt-level = 3`；发布构建使用 `panic = abort`、`lto = true`、`strip = true`。

---

## 11. 常用文档索引

| 文档 | 内容 |
|---|---|
| `README.md` / `README_EN.md` | 项目简介、快速开始、功能列表 |
| `docs/architecture.md` | 系统架构、数据包旅程、BPF Maps |
| `docs/distributed-architecture.md` | Hub-Node 架构与数据流 |
| `docs/deployment.md` | 二进制、systemd、容器、K8s、Hub 部署 |
| `docs/operations.md` | 日常运维、日志、告警、备份恢复、故障排查 |
| `docs/dev-linux.md` | 开发环境、依赖安装、本地构建测试 |
| `docs/api.md` | REST API 完整端点与认证说明 |
| `docs/benchmark.md` | 基准测试方法与示例报告 |

---

## 12. 修改本文件后的检查清单

当你新增/修改了以下内容时，请同步更新本文件：

- [x] 新增 Crate、模块或二进制。
- [x] 新增 CLI 子命令或配置段。
- [ ] 改变构建命令、目标平台或发布产物。
- [ ] 改变测试方式（新增集成测试脚本、CI 步骤）。
- [ ] 改变安全模型（认证方式、capability、持久化路径）。
- [ ] 改变部署方式（systemd、Docker、Hub）。

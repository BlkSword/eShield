# eShield

[English](README_EN.md) | 中文

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

eShield 是基于 eBPF/XDP 的主机级 L3-L4 网络防护系统，用于在 Linux 内核网络协议栈之前拦截 SYN Flood、UDP Flood、ICMP Flood、扫描探测与连接耗尽类流量。项目由 Rust 实现，包含 eBPF 数据面、用户态控制面、分布式策略 Hub、Web 控制台、CLI 与 TUI。

## 目录

- [1. 项目概述](#1-项目概述)
- [2. 能力范围](#2-能力范围)
- [3. 系统架构](#3-系统架构)
- [4. 环境要求](#4-环境要求)
- [5. 构建与安装](#5-构建与安装)
- [6. 快速开始](#6-快速开始)
- [7. 配置参考](#7-配置参考)
- [8. 运行时操作](#8-运行时操作)
- [9. 分布式 Hub](#9-分布式-hub)
- [10. 可观测性](#10-可观测性)
- [11. 性能特征](#11-性能特征)
- [12. 测试](#12-测试)
- [13. 项目结构](#13-项目结构)
- [14. 安全边界与限制](#14-安全边界与限制)
- [15. 文档索引](#15-文档索引)
- [16. 许可证](#16-许可证)

## 1. 项目概述

eShield 将过滤逻辑部署在网卡驱动层的 XDP 钩子上。数据包在进入内核协议栈之前完成解析、规则匹配与丢弃决策，避免恶意流量消耗协议栈、连接表和应用进程资源。

系统定位为**主机级第一道防线**，适用于单机、边缘节点、源站、游戏服务器与内部服务等场景。系统不替代云清洗、CDN 或运营商级 DDoS 清洗设备，无法突破物理链路带宽上限。

主要组成部分：

| 组件 | 说明 |
|---|---|
| `eshield-ebpf` | XDP/eBPF 数据面，负责每包解析、规则匹配、丢弃、TCP RST 与 SYN Cookie 回包。 |
| `eshield` | 用户态控制面，负责配置、API、Web 控制台、TUI、持久化、审计、告警与 Hub 同步。 |
| `eshield-common` | 数据面与控制面共享的结构体、常量与纯函数。 |
| `eshield-hub` | 分布式策略聚合服务，负责多节点策略共享、节点注册与每节点 Token 管理。 |
| `xtask` | 构建任务封装，固定 eBPF 工具链与目标平台。 |

## 2. 能力范围

### 2.1 数据面能力

| 能力 | 说明 |
|---|---|
| eBPF/XDP 早期过滤 | 在网卡驱动层完成丢弃决策，不经过内核协议栈。 |
| CIDR 白名单 | 基于 LPM Trie，支持 IPv4/IPv6，白名单命中后尽早放行。 |
| 动态黑名单 | 基于 LRU Hash，支持永久与限时封禁，到期自动解封。 |
| Per-IP 速率限制 | 指数衰减滑动窗口，用于识别突发连接与请求。 |
| 按目的端口限速 | 按协议与目的端口维度限速，降低换源 IP 绕过 per-IP 限速的风险。 |
| UDP/ICMP Flood 防护 | 对无连接流量执行 per-IP 与按端口速率抑制。 |
| 端口/协议 ACL | 支持 `tcp`、`udp`、`icmp`、`icmpv6`、`any`，支持端口、端口范围与通配。 |
| SYN Cookie 代理 | IPv4 TCP SYN Flood 场景下返回 SYN-ACK Cookie，验证合法 ACK 后放行。 |
| TCP RST 回包 | 对被丢弃的 TCP 连接回复 RST，减少客户端重传堆积。 |
| GeoIP/ASN 过滤 | 基于 CSV CIDR 列表按国家或 ASN 放行/封禁，支持 `default_action`。 |
| 威胁情报联动 | 定时同步外部 feed，批量写入黑名单或白名单。 |
| L7 指纹扫描 | 检查 TCP 首包特征，用于识别扫描与探测行为。 |
| 连接跟踪/CC 防御 | 可选模块，对单源半连接计数，仅 SYN/ACK/RST 访问 map，超阈值丢弃。 |
| 防护项目 | 按目标 IPv4、端口、协议组合策略，支持 PASS、DROP 与 DEFEND。 |
| 自适应阈值 | 按时间窗口聚合事件，对重复触发规则的源提升封禁时长。 |
| Trust Score | IP 双向信誉评分，PASS 加分、DROP 减分，动态调制速率阈值。 |
| Danger Signal | 根据系统负载与攻击强度调整全局危险等级与阈值。 |
| 数据包采样日志 | 按采样率上报 DROP 包，用于溯源与取证。 |

### 2.2 控制面与运维能力

| 能力 | 说明 |
|---|---|
| Web 控制台 | 原生 ES modules + 模块化 CSS，跟随系统亮/暗色，无装饰性图标，支持命令面板。 |
| CLI 与 TUI | `eshield start/status/block/unblock/reload/check/tui/reset-token`。 |
| 配置热加载 | 通过 `SIGHUP` 或 `systemctl reload` 重新加载配置。 |
| 认证 | 可选 Bearer Token；本机回环请求跳过 Token 校验。 |
| 持久化 | 动态规则与时序指标写入 redb，进程重启后恢复。 |
| 审计 | 内存或 JSON Lines 审计后端，支持 SSE 实时流与 CSV 导出。 |
| 指标 | Prometheus `/metrics` 与 JSON `/api/stats`。 |
| 告警 | 支持 Webhook 告警与阈值、冷却时间配置。 |
| 分布式策略 | Hub 聚合多节点策略；支持 master token 与每节点 Token。 |
| 内核兼容 | 固定 `nightly-2026-07-31` 与 `bpf-linker 0.10.4`；支持 `ESHIELD_XDP_MODE=skb` 规避虚拟网卡原生 XDP 问题。 |

## 3. 系统架构

```text
┌──────────────────────────────────────────────────────────────┐
│ 管理面                                                       │
│ Web 控制台（axum） │ CLI（clap） │ TUI（ratatui）            │
└──────────────────────────────┬───────────────────────────────┘
                               │ REST API / SSE / 配置监听
┌──────────────────────────────▼───────────────────────────────┐
│ 控制面（Rust 用户态）                                         │
│ 配置管理 │ 事件消费 │ 自适应引擎 │ 持久化 │ 指标 │ 审计 │ Hub │
└──────────────────────────────┬───────────────────────────────┘
                               │ BPF Maps / Ring Buffer
┌──────────────────────────────▼───────────────────────────────┐
│ 数据面（eBPF/XDP）                                           │
│ 包解析 → 白名单 → 端口 ACL → 黑名单 → 防护项目 → GeoIP      │
│ → 连接跟踪 → TCP（SYN Cookie/SYN Flood）→ UDP/ICMP Flood     │
│ → L7 指纹 → 速率限制 → Trust/统计 → 决策                    │
└──────────────────────────────────────────────────────────────┘
```

数据包旅程、BPF Map 布局与状态机细节见 [docs/architecture.md](docs/architecture.md)。

## 4. 环境要求

### 4.1 运行环境

- Linux 内核 5.10 或更高版本，并启用 BTF：

  ```bash
  ls /sys/kernel/btf/vmlinux
  ```

- root 权限或以下 capabilities：`CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_PERFMON`、`CAP_IPC_LOCK`。
- 支持 XDP 的网卡；虚拟网卡环境建议使用 SKB 通用模式。

### 4.2 构建环境

- stable Rust 工具链（构建用户态与 Hub）。
- nightly 工具链固定为 `nightly-2026-07-31`，用于 eBPF 构建，需要 `rust-src` 与 `clippy` 组件。
- `bpf-linker 0.10.4`。
- clang/LLVM、libelf、musl 工具链。
- `x86_64-unknown-linux-musl` Rust target。

构建工具链可通过以下环境变量覆盖：

| 变量 | 作用 |
|---|---|
| `ESHIELD_EBPF_TOOLCHAIN` | 覆盖 eBPF 构建使用的 nightly 工具链。 |
| `ESHIELD_XDP_MODE` | 设为 `skb` 或 `generic` 时强制 SKB 通用模式挂载。 |
| `ESHIELD_INTERFACE` | 覆盖配置中的监听网卡。 |

Windows 主机无法直接构建或运行本项目。构建与测试应在 WSL2、Linux 虚拟机或 Linux 云主机中进行。

## 5. 构建与安装

### 5.1 一键安装

```bash
sudo bash scripts/install.sh --build
```

安装脚本执行以下操作：

1. 使用固定 nightly 工具链构建 eBPF 程序。
2. 使用 musl target 静态构建用户态二进制。
3. 安装 `eshield` 到 `/usr/local/bin`。
4. 创建默认配置 `/etc/eshield/config.toml`。
5. 安装并启用 systemd 服务。

### 5.2 手动构建

```bash
export ESHIELD_EBPF_TOOLCHAIN=nightly-2026-07-31

cargo xtask build-ebpf
cargo build --package eshield --target x86_64-unknown-linux-musl --release
cargo build --package eshield-hub --release
```

构建产物：

```text
target/x86_64-unknown-linux-musl/release/eshield
target/release/eshield-hub
target/bpfel-unknown-none/release/eshield
```

eBPF 目标文件由 `include_bytes_aligned!` 嵌入用户态二进制，部署时仅需分发用户态可执行文件。

## 6. 快速开始

### 6.1 最小配置

```toml
interface = "eth0"
web_bind = "0.0.0.0:8720"
api_token = "replace-with-a-random-token"

whitelist = ["10.0.0.0/8"]
blacklist = []

[rate_limit]
enabled = true
threshold = 200
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 300

[syn_proxy]
enabled = true

[conn_track]
enabled = false
threshold = 20
window_ms = 10000
```

完整配置示例见 [packaging/config.example.toml](packaging/config.example.toml)。

### 6.2 启动

```bash
sudo eshield start --config /etc/eshield/config.toml
```

控制台默认监听 `http://<host>:8720/`。未设置 `api_token` 时，系统生成随机 Token 并在日志中输出前缀；可通过 `eshield reset-token` 重置。

### 6.3 systemd 管理

```bash
sudo systemctl start eshield
sudo systemctl status eshield
sudo systemctl stop eshield
sudo systemctl reload eshield
sudo journalctl -u eshield -f
```

`reload` 触发 `SIGHUP`，重新加载配置文件，不中断 XDP 挂载。

### 6.4 虚拟网卡测试模式

在 veth、bridge 等虚拟网卡上，原生 XDP_TX 可能触发内核异常。测试环境建议：

```bash
ESHIELD_XDP_MODE=skb sudo eshield start --config /etc/eshield/config.toml
```

集成测试脚本通过 `ESHIELD_TEST_XDP_MODE=skb` 统一使用 SKB 模式。

## 7. 配置参考

默认配置路径为 `/etc/eshield/config.toml`。

| 配置段 / 字段 | 作用 |
|---|---|
| `interface` | XDP 挂载网卡。 |
| `web_bind` | Web/API 监听地址，默认 `0.0.0.0:8720`。 |
| `api_token` | Bearer Token；未设置时生成随机 Token。 |
| `whitelist` / `blacklist` | 启动时加载的静态 CIDR 白名单与永久黑名单。 |
| `[rate_limit]` | per-IP 指数衰减速率限制与触发封禁时长。 |
| `[port_rate_limit]` | 按协议与目的端口的固定窗口限速。 |
| `[syn_proxy]` | IPv4 SYN Cookie 代理开关。 |
| `[udp_flood]` / `[icmp_flood]` | 无连接 Flood 防护开关。 |
| `[l7_scan]` | TCP 首包指纹匹配。 |
| `[adaptive]` | 重复触发规则的自动封禁窗口与阈值。 |
| `[geoip]` | 基于国家/地区或 ASN 的 CSV CIDR 放行/封禁。 |
| `[threat_intel]` | 外部威胁情报 feed 同步。 |
| `[trust_score]` | IP 双向信誉评分与除数配置。 |
| `[danger_signal]` | 系统危险等级监测与阈值调整。 |
| `[conn_track]` | 可选连接跟踪/半连接 CC 防御。 |
| `[port_acl]` | 端口/协议 allow/drop 规则。 |
| `[protection_projects]` | 按目标 IPv4、端口、协议组合的防护项目。 |
| `[packet_log]` | DROP 包采样日志。 |
| `[hub]` | 分布式 Hub 同步配置。 |
| `timeseries_retention_days` | 时序指标保留天数。 |
| `[audit]` | 审计后端与文件轮转配置。 |
| `[alert]` | Webhook 告警地址、类型、阈值与冷却时间。 |

配置约束：

- `protection_projects.target_ips` 不能为空，且至少包含一个 IPv4 目标；数据面仅支持 IPv4 精确匹配，CIDR 由控制面展开，下限为 `/24`，项目策略上限 8192 条。
- `port_acl` 最多 32 条，`l7_scan.patterns` 最多 8 条。该上限用于满足内核 7.0 verifier 的 100 万指令处理限制。
- `conn_track.threshold` 与 `conn_track.window_ms` 必须大于 0。

## 8. 运行时操作

### 8.1 CLI 命令

```bash
# 启动守护进程
sudo eshield start --config /etc/eshield/config.toml

# 查看本机状态
eshield status

# 封禁 IP；duration 为 0 表示永久
eshield block 192.0.2.1 --duration 300

# 解封 IP
eshield unblock 192.0.2.1

# 重新加载配置
eshield reload

# 校验配置
eshield check --config /etc/eshield/config.toml

# 启动 TUI
eshield tui

# 远程 API
eshield status --endpoint http://eshield-host:8720
eshield block 192.0.2.1 --endpoint http://eshield-host:8720

# 重置控制台 Token
eshield reset-token
```

### 8.2 认证规则

- 设置 `api_token` 后，Dashboard、`/api/*` 与 `/metrics` 需要 `Authorization: Bearer <token>`。
- 本机 CLI 通过回环地址访问时自动跳过 Token 校验。
- Web 控制台支持通过 `/login` 页面设置 Cookie，用于浏览器访问。

### 8.3 热加载

```bash
sudo systemctl reload eshield
sudo kill -HUP $(pidof eshield)
```

## 9. 分布式 Hub

`eshield-hub` 用于多节点策略聚合与共享。

### 9.1 启动 Hub

```bash
eshield-hub --bind 0.0.0.0:9930 --token "master-token"
```

生产环境应在 Hub 前部署 TLS 终止层，例如 nginx 或 Caddy。

### 9.2 每节点 Token

```bash
eshield-hub --bind 0.0.0.0:9930 \
  --token "master-token" \
  --node-tokens-file /etc/eshield-hub/node-tokens
```

`node-tokens` 文件每行格式为 `node_name:token`，支持 `#` 注释与空行。节点专属 Token 认证成功后，Hub 使用认证节点名记录策略与限流，避免请求体伪造 `node_name`。master token 保持兼容。

### 9.3 节点配置

```toml
[hub]
enabled = true
urls = ["https://hub.example.com:9930"]
node_name = "web-tier-01"
token = "node-token"
sync_pull_interval_s = 10
sync_push_interval_s = 5
sync_rules_enabled = true
```

节点在 Hub 不可用时保持本地策略自治，并自动重试同步。

## 10. 可观测性

### 10.1 Web 控制台

控制台默认地址为 `http://<host>:8720/`，采用跟随系统亮/暗色的扁平化设计，导航与操作均为文本标签，不包含装饰性图标。

页面组成：

| 页面 | 内容 |
|---|---|
| 总览 | 全部 KPI、流量与拦截趋势、拦截原因、TOP 攻击源与端口、最近攻击。 |
| 实时流量 | 数据包采样日志、协议/端口过滤、十六进制载荷查看。 |
| 攻击事件 | 事件列表、源 IP 详情抽屉、封禁、加白与解封操作。 |
| 防护模块 | 全部防护模块的开关与参数，改动即时生效。 |
| 防护规则 | 黑名单、白名单、端口 ACL、L7 指纹、防护项目、威胁情报。 |
| 安全运营 | 快速封禁、CIDR 放行、静态黑名单与白名单管理。 |
| 审计日志 | 操作审计、过滤、分页、SSE 实时流与 CSV 导出。 |
| 集群管理 | Hub 连接状态、节点列表、策略同步状态与每节点 Token。 |
| 系统设置 | 运行时信息、告警配置、Token 管理、原始配置查看。 |

控制台支持：

- `Ctrl/Cmd+K`：打开命令面板，执行页面跳转、聚焦搜索、重载配置。
- `g` 组合键：`g o` 总览、`g a` 攻击事件、`g t` 实时流量、`g l` 审计、`g p` 防护模块、`g r` 防护规则、`g s` 安全运营、`g c` 集群、`g ,` 设置。
- `/`：聚焦全局搜索。
- 主题跟随操作系统 `prefers-color-scheme`。

### 10.2 Prometheus 指标

```text
http://<host>:8720/metrics
```

主要指标包括：

- `eshield_dropped_total`
- `eshield_passed_total`
- `eshield_blacklist_blocked_total`
- `eshield_rate_limited_total`
- `eshield_syn_flood_blocked_total`
- `eshield_udp_flood_blocked_total`
- `eshield_icmp_flood_blocked_total`
- `eshield_geoip_blocked_total`
- `eshield_conn_track_blocked_total`
- `eshield_dropped_by_protocol_total`

### 10.3 JSON API

```bash
curl -H "Authorization: Bearer <token>" http://<host>:8720/api/stats | jq
```

完整 API 说明见 [docs/api.md](docs/api.md)。

### 10.4 审计

- `GET /api/audit`：查询审计事件，支持 `limit`、`ip`、`action`、`from`、`to`。
- `GET /api/audit/stream`：SSE 实时推送。
- 审计后端支持内存与 JSON Lines 文件；文件后端支持大小轮转。

### 10.5 TUI

```bash
eshield tui
```

## 11. 性能特征

### 11.1 设计目标

- 正常流量仅增加少量 eBPF map 查询与分支判断。
- 可选模块默认关闭；未启用模块在数据面快速跳过。
- 攻击期高频写路径采用采样与批量策略，降低 map 写放大。
- 控制面同步任务不位于每包路径。

### 11.2 veth 大包吞吐基准

测试环境：Linux 内核 7.0，8 vCPU，netns + veth，`iperf3 -c <server> -t 5 -P 4` 大包 TCP。

| 场景 | 吞吐 | 说明 |
|---|---:|---|
| Baseline（无 XDP） | 274.44 Gbps | veth 本机内存拷贝上限 |
| 最小 XDP_PASS 程序（原生模式） | 12.83 Gbps | veth 原生 XDP 自身瓶颈 |
| eShield PASS（原生模式，空规则） | 11.85 Gbps | 相对最小程序约 -7.6% |
| 最小 XDP_PASS 程序（SKB 通用模式） | 124.62 Gbps | 通用模式在 veth 上更快 |
| eShield PASS（SKB 通用模式，空规则） | 112.30 Gbps | 相对最小程序约 -9.9% |
| eShield PASS（原生模式，模块启用但不触发 DROP） | 11.81 Gbps | 相对空规则约 -0.3% |

基准结论：

- veth 原生 XDP 是主要瓶颈，eShield 程序相对最小 XDP_PASS 程序增加约 7%–10% 开销。
- 大包 TCP 场景下，启用速率限制、Trust、连接跟踪等模块后额外开销低于 1%。
- 大包 1500B 下，原生模式约 1 Mpps，SKB 通用模式约 9–10 Mpps。
- 小包、高 pps 与物理网卡线速必须通过真实网卡、`xdp-bench` 或 `pktgen` 复测，不能由本表推算。

### 11.3 高频写路径优化

| 路径 | 策略 |
|---|---|
| Trust PASS 更新 | 1/64 采样写入，按 64 倍权重补偿。 |
| Trust DROP 更新 | 信任分已归零的源 1/16 采样写入。 |
| Blacklist hit_count | 1/16 采样写入，单次补 16。 |
| TOP_ATTACKERS 热榜 | 1/16 采样写入，单次补 16。 |
| 黑名单命中 RingBuf 事件 | 不再写入，计数由全局统计与 hit_count 覆盖。 |

详细基准方法与数据见 [docs/benchmark.md](docs/benchmark.md)。

## 12. 测试

### 12.1 单元测试

```bash
cargo test --workspace --exclude eshield-ebpf
```

### 12.2 集成测试

集成测试需要 root 权限，并在 network namespace 中运行。虚拟网卡环境建议使用 SKB 模式。

```bash
sudo ESHIELD_TEST_XDP_MODE=skb bash tests/netns_test.sh
sudo ESHIELD_XDP_MODE=skb bash tests/hub_node_test.sh
sudo ESHIELD_XDP_MODE=skb bash tests/full_attack_test.sh
```

覆盖场景：

- 黑名单、TCP RST 回包、速率限制
- SYN Flood、SYN Cookie 挑战与合法连接恢复
- UDP Flood、ICMP Flood、L7 指纹
- SIGHUP 热加载与服务停止恢复
- 自适应阈值、GeoIP/ASN、威胁情报
- 防护项目 DROP、GeoIP allowlist、IPv4 分片
- 连接跟踪半连接拦截
- Hub 策略同步、解封、规则下发与每节点 Token

### 12.3 构建与静态检查

```bash
cargo fmt --all -- --check
cargo clippy --workspace --exclude eshield-ebpf -- -D warnings
cargo +nightly-2026-07-31 clippy --package eshield-ebpf \
  --target bpfel-unknown-none -Z build-std=core -- -D warnings
```

## 13. 项目结构

```text
.
├── eshield/            # 用户态控制面、Web 控制台、CLI、TUI
├── eshield-ebpf/       # eBPF/XDP 数据面
├── eshield-common/     # 共享结构体、常量与纯函数
├── eshield-hub/        # 分布式策略 Hub
├── xtask/              # eBPF 构建任务
├── scripts/            # 安装、卸载、基准与发布脚本
├── tests/              # 单元与集成测试脚本
├── docs/               # 架构、部署、运维、API、基准与开发文档
├── packaging/          # systemd、示例配置、容器与编排文件
├── README.md
├── README_EN.md
└── LICENSE
```

## 14. 安全边界与限制

- **主机级防护**：面向单机或边缘节点的 L3-L4 防护。T 级带宽耗尽型攻击需要上游云清洗或运营商清洗，eShield 无法突破物理链路上限。
- **L7 能力有限**：当前 L7 模块仅检查 TCP 首包指纹，不支持 TCP 分段重组，不提供 HTTP Flood、CC 或慢速攻击的完整应用层防御。
- **SYN Cookie 范围**：仅支持 IPv4 TCP，采用挑战模式，仅对超过阈值的源生效。
- **防护项目范围**：数据面仅匹配 IPv4 精确 IP，CIDR 由控制面展开，下限 `/24`，项目上限 8192 条。
- **规则容量限制**：`port_acl` 上限 32 条，`l7_scan.patterns` 上限 8 条，用于满足内核 7.0 verifier 的指令处理限制。
- **虚拟网卡限制**：veth 等虚拟网卡的原生 XDP_TX 存在内核异常风险，测试环境应使用 `ESHIELD_XDP_MODE=skb`。
- **平台限制**：不支持 Windows；不支持无 BTF 的内核。
- **物理网卡基准缺失**：当前公开基准基于 veth，物理网卡、多队列、小包 pps 与延迟需在目标环境实测。

## 15. 文档索引

| 文档 | 内容 |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | 运维与安全人员使用手册。 |
| [docs/architecture.md](docs/architecture.md) | 系统架构、数据包旅程与 BPF Maps。 |
| [docs/deployment.md](docs/deployment.md) | 二进制、systemd、容器、K8s 与 Hub 部署。 |
| [docs/operations.md](docs/operations.md) | 日常操作、日志、告警、备份恢复与故障排查。 |
| [docs/dev-linux.md](docs/dev-linux.md) | 依赖安装、构建与本地测试。 |
| [docs/api.md](docs/api.md) | REST API 端点、请求与响应示例。 |
| [docs/benchmark.md](docs/benchmark.md) | 基准测试方法与数据。 |

## 16. 许可证

Apache-2.0

# eShield 用户手册

> 适用版本：v0.4.2
> 阅读对象：已完成安装、需要日常运维与使用的安全/运维工程师。

---

## 目录

- [1. 产品概述](#1-产品概述)
- [2. 首次启动与登录](#2-首次启动与登录)
- [3. 控制台导览](#3-控制台导览)
  - [3.1 总览页](#31-总览页)
  - [3.2 攻击事件](#32-攻击事件)
  - [3.3 包日志](#33-包日志)
  - [3.4 防护策略](#34-防护策略)
  - [3.5 规则中心](#35-规则中心)
  - [3.6 安全运营](#36-安全运营)
  - [3.7 审计日志](#37-审计日志)
  - [3.8 设置](#38-设置)
- [4. 配置文件说明](#4-配置文件说明)
- [5. CLI 常用操作](#5-cli-常用操作)
- [6. 热加载与重启](#6-热加载与重启)
- [7. 数据持久化与备份](#7-数据持久化与备份)
- [8. 典型使用场景](#8-典型使用场景)
- [9. 告警与 Prometheus](#9-告警与-prometheus)
- [10. 常见问题与排查](#10-常见问题与排查)

---

## 1. 产品概述

eShield 是一款基于 eBPF/XDP 的主机级 L3-L4 网络清洗盾，运行在 Linux 内核的 XDP 钩子上，在恶意流量进入内核网络协议栈之前完成丢弃、挑战或放行。

它适合以下场景：

- 防御 SYN Flood、UDP Flood、ICMP Flood、CC 等网络层攻击。
- 对入口流量做 per-IP 速率限制、端口 ACL、GeoIP/ASN 过滤、威胁情报联动。
- 通过中文 Web 控制台、CLI、TUI、REST API 实时观测与运维。
- 多节点场景下通过 `eshield-hub` 共享黑名单与信誉。

> **定位**：eShield 是主机级清洗盾，无法突破物理带宽上限。T 级带宽耗尽型攻击需要上游云厂商黑洞/清洗配合。

---

## 2. 首次启动与登录

### 2.1 启动服务

安装完成后，使用 systemd 启动：

```bash
sudo systemctl enable --now eshield
```

或手动启动：

```bash
sudo eshield start --config /etc/eshield/config.toml
```

### 2.2 访问控制台

默认监听 `0.0.0.0:8720`，浏览器访问：

```
http://<服务器IP>:8720/
```

### 2.3 认证

- 若 `config.toml` 中未设置 `api_token`，外部访问默认匿名。
- 若设置了 `api_token`，登录页需要输入 Token；所有 `/api/*`、`/metrics` 端点也需要在请求头携带 `Authorization: Bearer <token>`。
- 本机 CLI（来源 `127.0.0.1/::1`）自动跳过 Token 校验。

Token 可通过以下方式重置：

```bash
sudo eshield reset-token
```

---

## 3. 控制台导览

控制台左侧为导航栏，右侧为主内容区。顶部显示系统状态（正常 / 警戒 / 危险）。

### 3.1 总览页

总览页展示实时安全态势：

- **核心指标卡片**：总丢弃包数、DPS、PPS、黑名单拦截、速率限制拦截、SYN Flood 拦截、UDP/ICMP 拦截、GeoIP/L7/自适应拦截、高信誉 IP 数、可疑/恶意 IP 数。
  - 卡片支持点击跳转：例如点击「黑名单拦截」跳到「规则中心」，点击「速率限制拦截」跳到「防护策略」。
- **流量与拦截趋势图**：支持 1 小时 / 6 小时 / 24 小时维度切换，展示 PPS、DPS、各类拦截原因的趋势曲线。
- **协议分布**、**TOP 被攻击端口**、**TOP 攻击源**：实时统计当前网络中的攻击画像。
- **最近拦截事件**：实时流展示最新被丢弃的包及其触发原因。

### 3.2 攻击事件

- 展示历史攻击事件列表，支持按时间、IP、原因筛选。
- 点击攻击源 IP 可打开 **IP 详情页**，查看该 IP 的：
  - 累计命中统计
  - 最近包日志采样
  - 该 IP 的时序曲线（PPS/DPS）
  - 一键封禁/解封操作

### 3.3 包日志

v0.4.2 新增。

- 仅对 **DROP 包**按 `sample_rate` 采样，避免高流量下消耗过多资源。
- 列表展示：时间、源 IP、目的 IP、协议、目的端口、触发原因、Payload 十六进制预览。
- 支持按源 IP 过滤，辅助溯源与取证。

> 默认采样率为 `1/10000`。若攻击流量极大且需要更详细样本，可适当调小；若控制台响应变慢，请调大采样率。

### 3.4 防护策略

统一配置全局模块开关与参数：

- 全局开关：速率限制、SYN Proxy、UDP Flood、ICMP Flood、L7 扫描、自适应阈值等。
- 速率限制参数：threshold、tick_ms、衰减因子、封禁时长。
- 自适应阈值参数：触发次数、窗口、封禁时长。
- 防护项目：按协议 + 端口 + 目标 IP 分组配置策略（控制面分组，数据面全局模块生效）。

修改后实时保存到运行时配置。

### 3.5 规则中心

集中管理静态与动态规则：

- **端口 / 协议 ACL**：对 tcp/udp/icmp/icmpv6/any 按端口或端口范围设置 allow/drop。
- **L7 指纹**：对 TCP 首包载荷做字节匹配，命中即 DROP。
- **GeoIP 配置**：加载自定义国家/ASN CSV 后，按国家代码或 ASN 放行/封禁。
- **威胁情报 Feeds**：配置自定义 feed URL，定时同步已知恶意 IP 并自动拦截。

### 3.6 安全运营

- **IP 封禁 / 解封**：输入 IP 与封禁时长（0 表示永久），实时写入动态黑名单。
- **放行 CIDR**：将可信网段加入白名单，永不被拦截。
- 所有操作会写入审计日志。

### 3.7 审计日志

- 记录 CLI/API/Web 的关键操作（封禁、解封、配置修改、登录、启动/停止等）。
- 支持关键字、IP、动作、时间范围筛选。
- 提供 SSE 实时流：`GET /api/audit/stream`。

### 3.8 设置

- 查看运行版本、进程启动时间、配置路径。
- 管理 `api_token`：显示/复制/重置。
- 切换主题（浅色 / 深色）。
- 手动触发「从配置文件重新加载」。

---

## 4. 配置文件说明

默认配置文件路径：`/etc/eshield/config.toml`。完整示例见 `packaging/config.example.toml`。

### 4.1 基础配置

| 配置项 | 说明 | 示例 |
|---|---|---|
| `interface` | 挂载 XDP 的网卡名 | `"eth0"` |
| `log_level` | 日志级别：`trace/debug/info/warn/error` | `"info"` |
| `log_json` | 是否输出 JSON 格式日志 | `false` |
| `ebpf_log_enabled` | 是否启用 eBPF 内核调试日志 | `false` |
| `udp_flood_enabled` | 是否启用 UDP Flood 检测 | `false` |
| `icmp_flood_enabled` | 是否启用 ICMP/ICMPv6 Flood 检测 | `false` |
| `web_bind` | Web/API 监听地址 | `"0.0.0.0:8720"` |
| `api_token` | 访问 Token（不设置则匿名） | `"changeme"` |
| `store_path` | 动态规则 redb 持久化路径 | `"/var/lib/eshield/rules.redb"` |
| `timeseries_retention_days` | 时序指标保留天数 | `30` |

### 4.2 告警配置

```toml
alert_webhook_type = "generic"   # generic / slack / dingtalk / wecom
alert_threshold_dps = 1000
alert_cooldown_s = 60
```

### 4.3 审计日志

```toml
[audit]
enabled = false
path = "/var/log/eshield/audit.log"
max_size_mb = 100
```

### 4.4 黑白名单

```toml
whitelist = ["127.0.0.1/32", "10.0.0.0/8"]
blacklist = ["192.0.2.1"]
```

### 4.5 速率限制

```toml
[rate_limit]
enabled = true
threshold = 200          # 每个 tick 允许的最大包数
tick_ms = 100            # 计数窗口
decay_num = 7
decay_den = 8            # 指数衰减因子 7/8
block_duration_s = 300   # 触发后封禁时长
```

### 4.6 SYN Cookie 代理

```toml
[syn_proxy]
enabled = false
```

> 仅支持 IPv4 TCP。启用后所有 SYN 都会受到 Cookie 挑战。

### 4.7 L7 扫描

```toml
[l7_scan]
enabled = false
patterns = [{ pattern = "ATTACKER" }]
```

> 仅检查 TCP 首包，不支持分段重组，不防御 HTTP Flood / CC / 慢速攻击。

### 4.8 自适应阈值

```toml
[adaptive]
enabled = true
threshold = 10      # window_s 内触发多少次后自动封禁
window_s = 5
block_duration_s = 300
```

### 4.9 GeoIP

```toml
[geoip]
enabled = false
country_blocks_csv = "/etc/eshield/geoip_country.csv"
block_countries = ["XX"]
default_action = "pass"
```

### 4.10 威胁情报

```toml
[threat_intel]
enabled = false

[[threat_intel.feeds]]
name = "abuseipdb"
url = "https://api.abuseipdb.com/api/v2/blacklist"
interval_s = 3600
action = "drop"
confidence = 80
```

### 4.11 包日志采样（v0.4.2）

```toml
[packet_log]
enabled = true
sample_rate = 10000       # 1/10000 采样
memory_max_entries = 50000
payload_hex = true
```

- `sample_rate`：数值越大采样越少，建议生产环境保持 `10000` 以上。
- `memory_max_entries`：内存中保留的最大条目数，超出后按 FIFO 淘汰。
- 仅对 DROP 包采样，PASS 包不记录。

### 4.12 分布式 Hub（v0.4.2）

```toml
[hub]
enabled = true
urls = ["https://hub.example.com:9930"]
node_name = "web-tier-01"
token = "change-me-to-a-long-random-string"
sync_pull_interval_s = 10
sync_push_interval_s = 5
push_min_hit_count = 10
sync_rules_enabled = false
```

---

## 5. CLI 常用操作

```bash
# 查看状态
eshield status

# 实时封禁 IP（300 秒）
eshield block 192.0.2.1 --duration 300

# 永久封禁
eshield block 192.0.2.1

# 解封
eshield unblock 192.0.2.1

# 重新加载配置文件
eshield reload

# 校验配置
eshield check --config /etc/eshield/config.toml

# 启动 TUI 仪表盘
eshield tui

# 重置控制台 Token
eshield reset-token

# 远程操作
eshield status --endpoint http://eshield-host:8720
eshield block 192.0.2.1 --endpoint http://eshield-host:8720
```

---

## 6. 热加载与重启

修改 `/etc/eshield/config.toml` 后，无需重启：

```bash
sudo systemctl reload eshield
# 或
sudo kill -HUP $(pidof eshield)
```

> 注意：部分配置（如 `interface`、`web_bind`、`store_path`）仅在进程启动时生效，热加载不会切换网卡或监听地址。

---

## 7. 数据持久化与备份

eShield 持久化以下数据到本地磁盘：

| 文件 | 路径 | 说明 |
|---|---|---|
| 动态规则库 | `/var/lib/eshield/rules.redb` | 黑名单、白名单、ACL、L7 指纹、威胁情报命中等 |
| 时序指标库 | `/var/lib/eshield/timeseries.redb` | 分钟级 PPS/DPS/拦截趋势，保留 `timeseries_retention_days` 天 |
| 审计日志 | `/var/log/eshield/audit.log` | 操作审计 JSON Lines（可选开启） |
| 配置文件 | `/etc/eshield/config.toml` | 静态配置 |

### 备份

```bash
sudo tar czf eshield-backup.tar.gz /etc/eshield /var/lib/eshield /var/log/eshield
```

### 恢复

```bash
sudo systemctl stop eshield
sudo tar xzf eshield-backup.tar.gz -C /
sudo systemctl start eshield
```

> 手动删除 `/var/lib/eshield/*.redb` 会导致历史规则/时序清空，重启后重新积累。

---

## 8. 典型使用场景

### 8.1 发现攻击源并封禁

1. 在「总览」页查看 TOP 攻击源。
2. 点击 IP 进入「IP 详情页」，查看其命中原因与时序曲线。
3. 点击「封禁此 IP」，设置封禁时长。

或直接使用 CLI：

```bash
eshield block 192.0.2.1 --duration 3600
```

### 8.2 分析被丢弃的包

1. 启用 `[packet_log]` 并设置合理采样率。
2. 进入「包日志」页，按源 IP 过滤。
3. 查看触发原因与 Payload 预览，辅助判断攻击类型。

### 8.3 抵御 SYN Flood

```toml
[syn_proxy]
enabled = true
```

然后热加载：

```bash
eshield reload
```

### 8.4 按国家封禁流量

准备 CSV：

```csv
network,country
192.0.2.0/24,XX
```

配置：

```toml
[geoip]
enabled = true
country_blocks_csv = "/etc/eshield/geoip_country.csv"
block_countries = ["XX"]
```

在控制台「规则中心」→「GeoIP 配置」中点击「重新加载 CSV」。

---

## 9. 告警与 Prometheus

### 9.1 Webhook 告警

配置 `alert_webhook_url` 后，当 DPS 超过 `alert_threshold_dps` 且超过冷却时间时，会推送 JSON：

```json
{
  "event": "alert",
  "dps": 1500,
  "threshold": 1000,
  "timestamp": "2026-07-14T13:00:00Z"
}
```

### 9.2 Prometheus 指标

访问：

```
http://<host>:8720/metrics
```

主要指标：

- `eshield_dropped_total`
- `eshield_passed_total`
- `eshield_blacklist_blocked_total`
- `eshield_rate_limited_total`
- `eshield_geoip_blocked_total`
- `eshield_syn_flood_blocked_total`
- `eshield_udp_flood_blocked_total`
- `eshield_icmp_flood_blocked_total`

---

## 10. 常见问题与排查

| 现象 | 可能原因 | 排查方法 |
|---|---|---|
| 服务无法启动 | 内核版本不足 / 未启用 BTF / 权限不足 | `uname -r`、`ls /sys/kernel/btf/vmlinux`、检查 capabilities |
| XDP 挂载失败 | 网卡不支持 native XDP | 查看日志，默认会自动回退到 generic 模式 |
| Dashboard 无法访问 | 防火墙/安全组未放行 8720 | `ss -tlnp \| grep 8720`、检查云厂商安全组 |
| 流量未被拦截 | 源 IP 在白名单 / 规则未启用 | 检查 `whitelist`、确认对应模块开关已启用 |
| 包日志为空 | 未启用 packet_log / 采样率过高 / 无 DROP 流量 | 检查 `[packet_log]`、确认有攻击流量 |
| 时序图空白 | 进程重启后数据清空 / 保留期已过 | 检查 `/var/lib/eshield/timeseries.redb` 是否存在 |
| 节点策略未同步 | Hub 不可达 / Token 错误 / `node_name` 冲突 | 查看 `/api/hub/status`、检查节点名唯一性 |

更多架构、开发、部署细节请参考：

- [architecture.md](architecture.md) — 系统架构与数据包旅程
- [deployment.md](deployment.md) — 二进制、systemd、容器、K8s 部署
- [operations.md](operations.md) — 运维命令与故障排查
- [api.md](api.md) — REST API 完整参考
- [distributed-architecture.md](distributed-architecture.md) — 分布式 Hub 架构

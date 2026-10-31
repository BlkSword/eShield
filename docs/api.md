> # eShield REST API 参考

> 版本：v0.5.0（2026-10-31）

> **v0.5.0 变更摘要**：
> - 新增 `GET /api/map-usage`（map 水位）与 `GET /api/audit/verify`（审计哈希链校验）；
> - `GET /api/auth/check` 由返回 `OK` 文本改为返回 `{"role":"admin"|"readonly"}`；
> - 新增只读 Token（`readonly_token`）：只允许 `GET/HEAD/OPTIONS`，写操作返回 403；
> - `GET/PATCH /api/config` 新增 `fragment_policy`、`rate_limit_block_mode`；`GET` 另返回 `audit_path`/`audit_enabled`；
> - `/api/stats` 新增 `port_rate_blocked`、`fragment_blocked`；`/metrics` 新增
>   `eshield_map_usage_ratio`、`eshield_fragment_blocked_total`、`eshield_port_rate_blocked_total`；
> - 新增规则/原因 ID：`FRAGMENT=14`（分片策略）、`PORT_RATE=15`（端口聚合限速）。

> **v0.4.5 破坏性变更**：`/api/attack-events` 与 `/api/packets` 返回的 `timestamp_ns` 字段语义由 **eBPF 单调时钟纳秒**（开机起算）改为 **wall-clock Unix 纳秒**（后端统一转换后返回）。此前依赖该字段自行对齐 `CLOCK_MONOTONIC` 的客户端需要改为按 Unix 时间戳处理。

## 认证

外部访问受保护端点时，若 `config.toml` 中设置了 `api_token`，需在请求头携带：

```
Authorization: Bearer <token>
```

认证支持两种角色（v0.5.0 RBAC-lite）：

| 凭据 | 角色 | 权限 |
|---|---|---|
| `api_token`（未配置时进程会生成随机 Token） | `admin` | 全部读写端点。 |
| `readonly_token`（顶层配置，可选） | `readonly` | 仅 `GET`/`HEAD`/`OPTIONS`；写方法返回 **403**。 |

- 本机 CLI 来源地址为 `127.0.0.1/::1`，自动跳过 token 校验（视为 `admin`）；
  但带 `X-Forwarded-For`/`X-Real-IP`/`Forwarded` 头的反向代理请求不享受该豁免。
- 浏览器登录后由后端下发 `eshield-token` HttpOnly Cookie，Cookie 与 Bearer 等价；
  只读 Token 不能用于 `POST /api/auth/login` 登录控制台。
- 写方法使用只读 Token 时返回：

```json
403 {"error": "read-only token: write operations are not permitted"}
```

  唯一的写方法例外是 `POST /api/auth/logout`（用于清理浏览器会话 Cookie）。

## 端点概览

| 端点 | 方法 | 说明 |
|---|---|---|
| `/healthz` | GET | 健康检查（仅表示进程存活） |
| `/ready` | GET | 就绪检查（v0.4.8 起反映真实挂载状态，见下方说明） |
| `/login` | GET | 控制台登录入口（Vue SPA，登录态由 SPA 处理） |
| `/blocked` | GET | 403 封禁示例页 |
| `/api/auth/login` | POST | 控制台登录验证（成功后下发 HttpOnly `eshield-token` Cookie） |
| `/api/auth/check` | GET | 校验当前凭据并返回角色（v0.5.0：JSON） |
| `/api/auth/logout` | POST | 清除控制台会话 Cookie（v0.4.8） |
| `/api/auth/reset-token` | POST | 重置访问令牌 |
| `/` | GET | Web Dashboard（Vue 3 单文件 SPA，`console/` 构建后嵌入 `eshield/web/app.html`） |
| `/api/stats` | GET | 运行统计 |
| `/api/attack-events` | GET | 攻击事件（DROP），`timestamp_ns` 为 wall-clock Unix 纳秒 |
| `/api/packets` | GET | 采样包日志，`timestamp_ns` 为 wall-clock Unix 纳秒 |
| `/api/config` | GET, PATCH | 读取/修改运行时配置 |
| `/api/config/reload` | POST | 从文件重新加载配置 |
| `/api/protection-modules` | GET | 防护模块列表与状态 |
| `/api/blacklist` | GET, POST, DELETE | 查询实时黑名单 / 封禁 / 解封 IP |
| `/api/whitelist` | GET, POST, DELETE | 查询 / 添加 / 移除 CIDR 白名单 |
| `/api/audit` | GET | 审计日志 |
| `/api/audit/stream` | GET | 审计日志 SSE |
| `/api/audit/verify` | GET | **v0.5.0**：审计文件哈希链校验 |
| `/api/metrics/series` | GET | 时序指标（附 wall-clock `timestamp_ns`，参数 `duration_s`） |
| `/api/metrics/attacker-series` | GET | 单 IP 时序 |
| `/api/map-usage` | GET | **v0.5.0**：eBPF map 条目数/上限/使用率 |
| `/api/ip-detail` | GET | 单 IP 详情（控制台 IP 抽屉） |
| `/api/ip-series` | GET | 单 IP 时序（控制台 IP 抽屉） |
| `/api/port-acl` | GET, POST | 端口 ACL |
| `/api/protection-projects` | GET, POST | 防护项目（v0.4.6 起 PASS/DROP 在数据面生效；target_ips 支持 CIDR，IPv4 下限 /24） |
| `/api/l7-patterns` | GET, POST | L7 指纹 |
| `/api/geoip/reload` | POST | 重新加载 GeoIP CSV |
| `/api/threat-intel/sync` | POST | 手动触发威胁情报同步 |
| `/api/hub/status` | GET | 节点到 Hub 的连接状态 |
| `/api/hub/proxy/stats` | GET | 通过节点代理访问 Hub 全局统计 |
| `/api/hub/proxy/policies` | GET | 通过节点代理访问 Hub 策略查询接口 |
| `/api/hub/proxy/nodes` | GET | 通过节点代理访问 Hub 节点列表 |
| `/metrics` | GET | Prometheus 指标 |

## 详细说明

### GET /api/stats

返回实时统计。

```json
{
  "total_dropped": 1234,
  "current_pps": 250000,
  "current_dps": 135000,
  "blacklist_blocked": 100,
  "rate_limited": 500,
  "syn_flood_blocked": 50,
  "l7_blocked": 30,
  "adaptive_blocked": 20,
  "udp_flood_blocked": 10,
  "icmp_flood_blocked": 5,
  "geoip_blocked": 0,
  "conn_track_blocked": 0,
  "tcp_rst_sent": 0,
  "tcp_rst_fail": 0,
  "tcp_rst_attempt": 0,
  "tcp_dropped": 900,
  "udp_dropped": 300,
  "icmp_dropped": 34,
  "other_dropped": 0,
  "top_attackers": [
    {"ip": "192.0.2.1", "count": 100},
    {"ip": "2001:db8::1", "count": 50}
  ],
  "top_ports": [{"port": 443, "count": 100}],
  "trust_trusted": 0,
  "trust_neutral": 0,
  "trust_suspicious": 0,
  "trust_malicious": 0,
  "danger_level": 0,
  "xdp_attached": true,
  "xdp_mode": "native",
  "port_rate_blocked": 0,
  "fragment_blocked": 0
}
```

- `port_rate_blocked`（v0.5.0）：协议+目的端口聚合限速（`PORT_RATE`）拦截数；
- `fragment_blocked`（v0.5.0）：分片策略（`FRAGMENT`）拦截数；
- `xdp_attached` / `xdp_mode`（v0.4.8）：XDP 是否真的挂在网卡上、挂载模式（`native`/`generic`/`unknown`）；
- `danger_level`：全局危险等级 0/1/2；`trust_*`：Trust Score 分布。

### GET /api/config

返回当前运行时配置快照（`RuntimeConfigSnapshot`），主要字段：

```json
{
  "version": "0.5.0",
  "interface": "eth0",
  "web_port": 8720,
  "web_bind": "0.0.0.0:8720",
  "log_level": "info",
  "log_json": false,
  "store_path": "/var/lib/eshield/rules.redb",
  "rate_limit_enabled": true,
  "syn_proxy_enabled": false,
  "l7_scan_enabled": false,
  "udp_flood_enabled": false,
  "icmp_flood_enabled": false,
  "geoip_enabled": false,
  "tcp_reset_on_drop": false,
  "trust_enabled": false,
  "conn_track_enabled": false,
  "conn_track_threshold": 20,
  "conn_track_window_ms": 10000,
  "trust_add_divisor": 100,
  "trust_sub_divisor": 3,
  "geoip_default_action": 0,
  "danger_level": 0,
  "rate_limit": {
    "enabled": true,
    "threshold": 2000,
    "tick_ms": 100,
    "decay_num": 7,
    "decay_den": 8,
    "block_duration_s": 120,
    "dport_grouping": false
  },
  "port_rate_limit": {
    "enabled": true,
    "threshold": 2000,
    "tick_ms": 100,
    "decay_num": 0,
    "decay_den": 0,
    "block_duration_s": 0,
    "dport_grouping": false
  },
  "fragment_policy": "rate_limit",
  "rate_limit_block_mode": "hard",
  "audit_path": "/var/log/eshield/audit.log",
  "audit_enabled": false,
  "adaptive": { "...": "..." },
  "port_acl": [],
  "protection_projects": [],
  "l7_scan": { "...": "..." },
  "geoip": { "...": "..." },
  "threat_intel_feeds": [],
  "whitelist_entries": ["10.0.0.0/8"],
  "blacklist_entries": [],
  "hub_enabled": false,
  "hub_node_name": "",
  "hub_urls": [],
  "packet_log_enabled": false,
  "packet_log_sample_rate": 10000,
  "protection_projects_enabled": false
}
```

v0.5.0 新增字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `fragment_policy` | string | 非首片 IPv4 分片策略：`pass` / `rate_limit` / `drop`，默认 `rate_limit`。 |
| `rate_limit_block_mode` | string | 限速超限处置：`hard`（写黑名单）/ `soft`（只丢弃），默认 `hard`。 |
| `audit_enabled` | bool | 文件审计后端是否启用。 |
| `audit_path` | string | 审计文件路径（供 `/api/audit/verify` 使用）。 |

> 出于安全考虑，`api_token`、`readonly_token` 不会出现在任何响应中；
> `[limits]` 配置也不在快照中。

### PATCH /api/config

实时修改运行时开关与阈值，**立即生效**并写入数据面 `CONFIG`/`RATE_LIMIT_CFG` 等 map。
成功时返回纯文本 `配置已更新`；失败返回 `{"error":"..."}`（沿用现有错误约定）。

v0.5.0 可写字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `fragment_policy` | string | `pass` / `rate_limit` / `drop`；取值非法时报错。 |
| `rate_limit_block_mode` | string | `hard` / `soft`；取值非法时报错。 |
| `rate_limit` | object | `RateLimitParams`：`enabled`/`threshold`/`tick_ms`/`decay_num`/`decay_den`/`block_duration_s`/`dport_grouping`。 |
| `port_rate_limit` | object | 同上结构，但只读取 `enabled`/`threshold`/`tick_ms`（固定窗口，不做衰减）。 |
| `adaptive` | object | `AdaptiveConfig`。 |
| `rate_limit_enabled` / `syn_proxy_enabled` / `l7_scan_enabled` / `udp_flood_enabled` / `icmp_flood_enabled` / `geoip_enabled` / `tcp_reset_on_drop` / `trust_enabled` / `conn_track_enabled` | bool | 模块开关。 |
| `conn_track_threshold` / `conn_track_window_ms` | number | 连接跟踪参数（必须 > 0）。 |
| `trust_add_divisor` / `trust_sub_divisor` | number | Trust Score 除数（必须 > 0）。 |
| `geoip_default_action` | number | 0=pass（仅按 block 列表拦截）/ 1=drop（仅放行 allow 列表）。 |

示例：

```json
{
  "rate_limit_enabled": true,
  "udp_flood_enabled": true,
  "fragment_policy": "rate_limit",
  "rate_limit_block_mode": "soft",
  "rate_limit": {
    "enabled": true,
    "threshold": 2000,
    "tick_ms": 100,
    "decay_num": 7,
    "decay_den": 8,
    "block_duration_s": 120,
    "dport_grouping": false
  },
  "port_rate_limit": {
    "enabled": true,
    "threshold": 2000,
    "tick_ms": 100
  }
}
```

> `PATCH` 只影响运行时，不会写回 `/etc/eshield/config.toml`；
> 重启或 `POST /api/config/reload` 后会回到配置文件中的值。

### POST /api/config/reload

从磁盘重新加载配置文件。

### GET /api/auth/check

校验当前凭据并返回角色（v0.5.0）。

```json
{"role": "admin"}
```

```json
{"role": "readonly"}
```

### GET /api/map-usage（v0.5.0）

返回每个 eBPF map 的条目数、容量与使用率。数据来自后台采样缓存
（`metrics_interval_s`，默认 30s），抓取路径不加锁、不遍历大表。

```json
{
  "maps": [
    {"name": "BLACKLIST", "type": "LruHashMap", "entries": 12000, "max": 100000, "ratio": 0.12},
    {"name": "RATE_MAP", "type": "LruHashMap", "entries": 18100, "max": 100000, "ratio": 0.181},
    {"name": "CONFIG", "type": "Array", "entries": 0, "max": 1, "ratio": 0.0}
  ],
  "warn_threshold": 0.8,
  "sampled_ns": 1761234567890000000
}
```

- `entries` 只对 LRU 表有真实采样值（`BLACKLIST`/`RATE_MAP`/`RATE_MAP_PORT`/`TRUST_MAP`/
  `CONN_TRACK`/`SYN_PROXY_CONN`/`TOP_ATTACKERS`/`PROJECT_POLICY`）；Array/RingBuf/LPM 表固定为 0；
- `warn_threshold` 固定 0.8，运维侧告警阈值可自定；
- 容量估算与告警规则见 [operations.md](operations.md) 与 [capacity-planning.md](capacity-planning.md)。

### GET /api/audit/verify（v0.5.0）

校验文件审计后端的哈希链完整性（每条记录含 `seq`/`prev_hash`/`hash`，
`hash = sha256(seq|prev_hash|规范化内容)`）。

```json
{"ok": true, "checked": 1024, "first_bad_seq": null, "path": "/var/log/eshield/audit.log"}
```

```json
{"ok": false, "checked": 900, "first_bad_seq": 513, "path": "/var/log/eshield/audit.log"}
```

- 文件审计未启用时返回 `{"ok":true,"enabled":false,"message":"..."}`；
- 只能校验当前 `audit.path` 指向的单个文件；轮转后的 `audit.log.1~.3` 不在校验范围
  （详见 [operations.md](operations.md) 的审计链巡检建议）；
- 读取/解析审计文件失败时返回 500 `{"error":"..."}`。

### GET /api/blacklist

返回当前仍有效的黑名单条目（来自 eBPF `BLACKLIST` 实时表）。

```json
{
  "entries": [
    {"ip": "203.0.113.9", "reason": "黑名单", "origin": "api", "created_ns": 0, "expires_ns": 0, "hits": 9812443}
  ],
  "count": 1
}
```

### GET /api/whitelist

返回当前白名单 CIDR。

```json
{
  "entries": [{"cidr": "10.0.0.0/8", "note": "内网"}],
  "count": 1
}
```

### POST /api/blacklist

封禁 IP。

```json
{
  "ip": "192.0.2.1",
  "duration_s": 300
}
```

`duration_s` 为 0 表示永久。

### DELETE /api/blacklist

解封 IP。

```json
{
  "ip": "192.0.2.1"
}
```

### POST /api/whitelist

放行 CIDR。

```json
{
  "cidr": "10.0.0.0/8"
}
```

### DELETE /api/whitelist

移除 CIDR 放行。

```json
{
  "cidr": "10.0.0.0/8"
}
```

### GET /metrics

Prometheus 指标。v0.5.0 新增：

| 指标 | 类型 | 说明 |
|---|---|---|
| `eshield_map_usage_ratio{interface,name}` | gauge | map 使用率（entries/max_entries），仅采样表有值。 |
| `eshield_map_entries{interface,name}` | gauge | 采样表当前条目数。 |
| `eshield_map_max_entries{interface,name,map_type}` | gauge | map 容量（启动时采集，不变）。 |
| `eshield_fragment_blocked_total{interface,policy}` | counter | 分片策略拦截数，`policy` 为当前策略。 |
| `eshield_port_rate_blocked_total{interface}` | counter | 端口聚合限速拦截数。 |

已有指标：`eshield_dropped_total`、`eshield_passed_total`、`eshield_blacklist_blocked_total`、
`eshield_rate_limited_total`、`eshield_syn_flood_blocked_total`、`eshield_l7_blocked_total`、
`eshield_adaptive_blocked_total`、`eshield_udp_flood_blocked_total`、`eshield_icmp_flood_blocked_total`、
`eshield_geoip_blocked_total`、`eshield_conn_track_blocked_total`、
`eshield_dropped_by_protocol_total{protocol}`、`eshield_dropped_by_port_total{port}`、
`eshield_source_dropped_total{ip}`、`eshield_event_consumer_duration_us`（直方图）。

> 指标抓取需要 `api_token` 或 `readonly_token`（GET 即可）。

### GET /healthz

进程存活检查。

### GET /ready

服务就绪检查。v0.4.8 起不再只检查"程序对象是否存在"，而是检查 **XDP 是否真的挂在网卡上**
（由后台任务每 15s 校验）：

- 已挂载：`200 {"status":"ready","xdp_attached":true,"xdp_mode":"native|generic"}`
- 未挂载/被摘掉/重挂失败：`503 {"status":"not ready","xdp_attached":false,"xdp_mode":"...","error":"XDP program is not attached to the interface"}`

`/healthz` 只表示进程存活，不反映防护是否生效。

## 错误码约定

所有 JSON 错误响应统一为：

```json
{"error": "错误说明"}
```

| 状态码 | 含义 |
|---|---|
| 400 | 参数解析/校验错误（如非法 IP/CIDR、Port ACL 与防护项目条目非法）。 |
| 401 | 未携带/携带错误的 Token（`/login` 页面会重定向）。 |
| 403 | 只读 Token 执行写操作；或命中封禁页。 |
| 413 | 请求体超过上限（`PAYLOAD_TOO_LARGE`）。 |
| 429 | 登录失败次数过多（`TOO_MANY_REQUESTS`）。 |
| 500 | 内部错误；`PATCH /api/config` 的参数校验失败也走 500（沿用现有实现，便于前端统一处理）。 |

---

## Hub API（v0.4.2）

Hub 独立运行在 `:9930`，所有接口都需要 `Authorization: Bearer <hub_token>`。

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api/v1/policies` | GET | 拉取增量策略（`since`、`limit`） |
| `/api/v1/policies` | POST | 节点上报本地策略 |
| `/api/v1/policies` | DELETE | 撤回共享策略（生成 tombstone） |
| `/api/v1/policies/deleted` | GET | 拉取已删除策略（tombstone） |
| `/api/v1/rules` | GET | 获取当前规则包 |
| `/api/v1/rules` | POST | 统一下发规则包（ACL/L7/防护项目） |
| `/api/v1/nodes` | GET | 在线节点列表 |
| `/api/v1/nodes/heartbeat` | POST | 节点心跳 |
| `/api/v1/stats` | GET | 全局聚合统计 |

### POST /api/v1/policies

节点上报：

```json
{
  "node_name": "web-tier-01",
  "policies": [
    {
      "ip": { "family": 4, "addr": [0,0,0,0,0,0,0,0,0,0,0,0,10,0,0,2], "padding": [0,...] },
      "reason": 2,
      "hit_count": 150,
      "trust_score": 0,
      "blocked_until_ns": 1750819200000000000,
      "ttl_s": 300
    }
  ]
}
```

### GET /api/v1/policies?since=...

Hub 返回：

```json
{
  "policies": [
    {
      "ip": { "family": 4, "addr": [...], "padding": [...] },
      "reason": 2,
      "hit_count": 150,
      "trust_score": 0,
      "first_seen_ns": 1750819100000000000,
      "last_seen_ns": 1750819200000000000,
      "source_nodes": ["web-tier-01"],
      "ttl_s": 300
    }
  ],
  "cursor": "1750819200000000000",
  "deleted": [],
  "deleted_cursor": "0"
}
```

### POST /api/v1/rules

统一下发规则包：

```json
{
  "port_acl": [{"protocol": "tcp", "dport": "9999", "action": "drop"}],
  "l7_patterns": [{"pattern": "EVIL"}],
  "protection_projects": [
    {"name": "hub-test", "protocol": "tcp", "dport": "9999", "target_ips": ["10.0.0.1/32"], "enabled_modules": ["syn_flood"], "action": "defend"}
  ],
  "updated_at_ns": 1750819200000000000
}
```

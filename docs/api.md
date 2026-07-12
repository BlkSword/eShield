> # eShield REST API 参考

> 版本：v0.4.2

## 认证

外部访问受保护端点时，若 `config.toml` 中设置了 `api_token`，需在请求头携带：

```
Authorization: Bearer <token>
```

本机 CLI 来源地址为 `127.0.0.1/::1`，自动跳过 token 校验。

## 端点概览

| 端点 | 方法 | 说明 |
|---|---|---|
| `/healthz` | GET | 健康检查 |
| `/ready` | GET | 就绪检查 |
| `/login` | GET | 控制台登录页 |
| `/blocked` | GET | 403 封禁示例页 |
| `/api/auth/login` | POST | 控制台登录验证 |
| `/api/auth/check` | GET | 登录状态检查 |
| `/api/auth/reset-token` | POST | 重置访问令牌 |
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
| `/api/port-acl` | GET, POST | 端口 ACL |
| `/api/protection-projects` | GET, POST | 防护项目 |
| `/api/l7-patterns` | GET, POST | L7 指纹 |
| `/api/geoip/reload` | POST | 重新加载 GeoIP CSV |
| `/api/threat-intel/sync` | POST | 手动触发威胁情报同步 |
| `/api/hub/status` | GET | 节点到 Hub 的连接状态 |
| `/api/hub/proxy/policies` | GET/POST/DELETE | 通过节点代理访问 Hub 策略接口 |
| `/api/hub/proxy/rules` | GET/POST | 通过节点代理访问 Hub 规则接口 |
| `/api/hub/proxy/nodes` | GET | 通过节点代理访问 Hub 节点列表 |
| `/metrics` | GET | Prometheus 指标 |

## 详细说明

### GET /api/stats

返回实时统计。

```json
{
  "total_dropped": 1234,
  "blacklist_blocked": 100,
  "rate_limited": 500,
  "syn_flood_blocked": 50,
  "l7_blocked": 30,
  "adaptive_blocked": 20,
  "udp_flood_blocked": 10,
  "icmp_flood_blocked": 5,
  "top_attackers": [
    {"ip": "192.0.2.1", "count": 100},
    {"ip": "2001:db8::1", "count": 50}
  ]
}
```

### GET /api/config

返回当前运行时配置快照。

### PATCH /api/config

实时修改运行时开关与阈值。

```json
{
  "rate_limit_enabled": true,
  "syn_proxy_enabled": false,
  "l7_scan_enabled": false,
  "udp_flood_enabled": true,
  "icmp_flood_enabled": true,
  "rate_limit": {
    "enabled": true,
    "threshold": 200,
    "tick_ms": 100,
    "decay_num": 7,
    "decay_den": 8,
    "block_duration_s": 300
  }
}
```

### POST /api/config/reload

从磁盘重新加载配置文件。

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

Prometheus 指标。

### GET /healthz

进程存活检查。

### GET /ready

服务就绪检查（eBPF 已挂载、接口正常）。

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
    {"name": "hub-test", "protocol": "tcp", "dport": "9999", "target_ips": [], "enabled_modules": ["syn_flood"], "action": "defend"}
  ],
  "updated_at_ns": 1750819200000000000
}
```

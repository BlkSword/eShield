> # eShield REST API 参考

> 版本：v0.1.2

## 认证

默认启用 API Token 认证。在请求头中携带：

```
Authorization: Bearer <token>
```

Token 在 `config.toml` 的 `[auth]` 段配置。未配置或为空时关闭认证（不推荐用于生产）。

## 端点

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

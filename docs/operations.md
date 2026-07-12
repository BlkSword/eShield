# eShield 运维手册

## 常用命令

```bash
# 查看状态
eshield status

# 实时封禁 IP（300 秒）
eshield block 192.0.2.1 --duration 300

# 永久封禁
eshield block 192.0.2.1

# 解封
eshield unblock 192.0.2.1

# IPv6 同样支持
eshield block 2001:db8::1 --duration 600

# 重载配置
eshield reload

# 启动 TUI 仪表盘
eshield tui
```

## 日志

默认输出到 journald：

```bash
sudo journalctl -u eshield -f
```

可配置 JSON 结构化日志以便对接 ELK/Loki：

```toml
[log]
format = "json"
```

## 告警 Webhook

```toml
[alert]
webhook_url = "https://hooks.slack.com/services/xxx"
threshold_dps = 1000   # 每秒 DROP 包数超过该值触发
```

## 备份与恢复

```bash
# 备份配置和动态规则库
sudo tar czf eshield-backup.tar.gz /etc/eshield /var/lib/eshield

# 恢复
sudo tar xzf eshield-backup.tar.gz -C /
```

## 故障排查

| 现象 | 排查 |
|---|---|
| XDP 挂载失败 | 检查内核版本、BTF、capability |
| 流量未按预期 DROP | 检查白名单是否覆盖、规则优先级 |
| 日志无 eBPF 事件 | 确认 `ebpf_log_enabled = true` 且内核支持 perf event |
| Dashboard 无法访问 | 检查防火墙与 `web_port` |
| Hub 连接失败 | 检查节点 `[hub]` token/url；确认 Hub 可达；查看 `/api/hub/status` |
| 策略未同步 | 检查 `sync_pull_interval_s` / `sync_push_interval_s`；确认 `push_min_hit_count` 阈值 |
| 节点被封禁自己的策略 | 确认 `node_name` 在集群内唯一；Hub 会跳过来源为本节点的策略 |

## 分布式 Hub 运维

### 查看节点连接状态

```bash
# 节点侧
eshield status --endpoint http://node:8720
# 或
node_curl /api/hub/status
```

### 手动触发同步

```bash
# Hub 侧查看策略
curl -H "Authorization: Bearer <hub_token>" 'http://hub:9930/api/v1/policies?since=0&limit=100'

# 节点侧查看 Hub 代理
curl -H "Authorization: Bearer <node_token>" 'http://node:8720/api/hub/proxy/policies?since=0&limit=100'
```

### 备份 Hub 数据

```bash
sudo tar czf eshield-hub-backup.tar.gz /var/lib/eshield-hub
```

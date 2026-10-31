# eShield 运维手册

> 版本：v0.5.0（2026-10-31）
>
> 覆盖日常运维、升级/回滚/卸载、认证与 RBAC、审计链校验、map 水位告警、低内存行为与故障排查。
> 容量与规格见 [capacity-planning.md](capacity-planning.md)；能力边界见 [capability-boundaries.md](capability-boundaries.md)。

## `/ready` 返回 503 的含义（v0.4.8）

`/ready` 不再只表示"进程活着"，而是"XDP 程序确实挂在网卡上"。返回 503 且
`xdp_attached=false` 表示防护已失效（程序被驱动重置、外部 `ip link set ... xdp off`、
或自动重挂失败），此时流量是**裸奔**状态。处理：查看日志中的 `XDP 自动重挂失败`，
确认网卡存在、权限足够（CAP_NET_ADMIN/BPF），必要时重启进程。`/healthz` 只表示进程存活。

> 监控告警应以 `/ready` 为准，而不是 `/healthz`。

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

# 校验配置（不启动、不做内存预检）
eshield check --config /etc/eshield/config.toml

# 启动 TUI 仪表盘
eshield tui

# 查看当前版本（本机免 token）
curl -s http://127.0.0.1:8720/api/config | jq -r .version
```

## 升级 / 回滚 / 卸载

安装与升级统一由 `scripts/install.sh` 完成，支持指定版本、SHA256 校验、回滚与卸载。

```bash
# 查看全部参数
sudo bash scripts/install.sh --help
```

| 参数 | 说明 |
|---|---|
| `--build` | 从当前源码构建并安装（默认从 GitHub Release 下载）。 |
| `--version <x.y.z>` | 指定安装/升级的版本号（默认取仓库版本或 Release；`--build` 时实际版本以源码 `Cargo.toml` 为准）。 |
| `--sha256 <hex>` | 校验下载产物的 SHA256；也可用环境变量 `ESHIELD_EXPECTED_SHA`。仅对下载安装生效，`--build` 不校验。 |
| `--rollback [dir]` | 回滚到指定备份目录；省略目录时回滚到**最近一次**备份。 |
| `--uninstall` | 卸载：停止并禁用服务、移除二进制与 systemd 单元，**默认保留**配置与数据。 |
| `--purge` | 与 `--uninstall` 搭配：额外删除 `/etc/eshield`、持久化数据目录与 `/var/log/eshield`。 |

### 升级

```bash
# 1) 低峰期执行；升级会停止旧进程再启动新进程，XDP 需要重新挂载（秒级防护空窗）
sudo bash scripts/install.sh --version 0.5.0

# 2) 可选：同时校验下载产物 SHA256
sudo bash scripts/install.sh --version 0.5.0 --sha256 <官方发布的 sha256>

# 3) 升级后确认版本与状态
curl -s http://127.0.0.1:8720/api/config | jq -r .version
curl -s http://127.0.0.1:8720/ready
sudo systemctl status eshield
sudo eshield check --config /etc/eshield/config.toml
```

升级流程（脚本行为）：

1. 检测到已安装的 `eshield` 时，**先备份**当前二进制、配置与 systemd 单元到
   `/var/lib/eshield/backup/<YYYYmmdd-HHMMSS>/`（可用 `ESHIELD_BACKUP_DIR` 覆盖根目录），
   只保留最近 **5** 份；
2. 停止旧服务（避免覆盖正在运行的二进制）；
3. 下载/构建新版本，校验 ELF 头与 `SHA256SUMS`（设置了 `--sha256` 时再校验指定哈希）；
4. 安装二进制到 `/usr/local/bin/eshield`；**已存在的 `/etc/eshield/config.toml` 不会被覆盖**；
5. `daemon-reload` 并启动服务。

备份目录内容：

```text
/var/lib/eshield/backup/20261031-120000/
├── eshield            # 旧二进制
├── config.toml        # 旧配置
├── eshield.service    # 旧 systemd 单元
└── VERSION            # 旧版本号
```

### 回滚

```bash
# 回滚到最近一次备份
sudo bash scripts/install.sh --rollback

# 或指定备份目录
sudo bash scripts/install.sh --rollback /var/lib/eshield/backup/20261030-090000

# 回滚后确认
curl -s http://127.0.0.1:8720/ready
```

回滚会停服务 → 恢复二进制/配置/systemd 单元 → 启动服务；**不恢复** redb 规则库与审计日志
（这些数据在升级过程中未被修改，无需回滚）。

### 卸载

```bash
# 卸载，保留配置与数据（可随时重新安装恢复）
sudo bash scripts/install.sh --uninstall

# 彻底删除（配置、持久化规则库、审计日志一并清理，不可恢复）
sudo bash scripts/install.sh --uninstall --purge
```

`--purge` 删除的目录：`/etc/eshield`、`store_path` 所在目录（默认 `/var/lib/eshield`）、
`/var/log/eshield`。卸载不会自动删除 `/var/lib/eshield/backup`（除非落在被删目录内），
需要时手工清理。

> 卸载前建议先备份：`sudo tar czf eshield-backup.tar.gz /etc/eshield /var/lib/eshield`。

## 认证与只读 Token（RBAC-lite，v0.5.0）

```toml
api_token = "admin-读写-token"
readonly_token = "readonly-监控-token"   # 新增，可选
```

| 凭据 | 权限 |
|---|---|
| `api_token`（或未配置时自动生成的随机 Token） | `admin`：全部读写 API。 |
| `readonly_token` | `readonly`：仅允许 `GET` / `HEAD` / `OPTIONS`；写操作返回 **403**。 |
| 本机回环（`127.0.0.1`/`::1`，且不带反代头） | 视为 `admin`，免 Token。 |

只读 Token 适合：Prometheus 抓取 `/metrics`、只读大屏、第三方监控系统。

```bash
# 只读查询：正常返回 200
curl -H "Authorization: Bearer $READONLY_TOKEN" http://<host>:8720/api/stats

# 确认当前凭据角色：{"role":"readonly"}
curl -H "Authorization: Bearer $READONLY_TOKEN" http://<host>:8720/api/auth/check

# 写操作：403
curl -X POST -H "Authorization: Bearer $READONLY_TOKEN" \
  http://<host>:8720/api/blacklist -d '{"ip":"192.0.2.1","duration_s":60}'
# {"error":"read-only token: write operations are not permitted"}
```

注意事项：

- 只读 Token 不能用于控制台登录（`POST /api/auth/login` 只校验 `api_token`）；
  唯一的写方法例外是 `POST /api/auth/logout`（用于清理浏览器会话 Cookie）。
- 修改 `api_token` / `readonly_token` 后需要**重启**服务生效（SIGHUP 热加载不会更新认证凭据）。
- 两个 Token 都不要写进仓库；建议 `chmod 600 /etc/eshield/config.toml`。
- 只读 Token 泄露仍可读取全部统计与审计查询结果，按"只给需要的监控系统"发放。

## 审计哈希链校验（v0.5.0）

开启文件审计后端后，每条审计记录都会追加三个字段：

```json
{"seq":42,"prev_hash":"<上一条 hash>","hash":"<sha256(seq|prev_hash|规范化内容)>"}
```

- `seq` 单调递增，`hash` 与 `prev_hash` 首尾相连形成哈希链；任何记录被**改写、删除、插入**
  都会在断点处被发现；
- 进程重启后自动从文件尾部恢复链（继续追加，不会破坏已有校验）；
- 校验接口：`GET /api/audit/verify`。

```toml
[audit]
enabled = true
path = "/var/log/eshield/audit.log"
max_size_mb = 100
```

```bash
# 校验（admin 或只读 Token 均可，GET）
curl -s -H "Authorization: Bearer $TOKEN" http://<host>:8720/api/audit/verify | jq
```

返回示例：

```json
// 链完整
{"ok": true, "checked": 1024, "first_bad_seq": null, "path": "/var/log/eshield/audit.log"}

// 断链：从 seq=513 开始不一致
{"ok": false, "checked": 900, "first_bad_seq": 513, "path": "/var/log/eshield/audit.log"}

// 未开启文件审计后端
{"ok": true, "enabled": false, "message": "文件审计后端未启用（[audit].enabled = false）"}
```

**定期巡检建议**：

```bash
# 每天凌晨校验一次并归档结果；ok=false 时告警
0 3 * * * root curl -sf -H "Authorization: Bearer $(cat /etc/eshield/ro.token)" \
  http://127.0.0.1:8720/api/audit/verify > /var/log/eshield/verify-$(date +\%F).json
```

- `ok=false` 的排查顺序：确认是否有人工编辑/截断文件、磁盘是否写满、是否发生过轮转或外部
  工具改写；`first_bad_seq` 之前的记录可信，之后的记录需要与操作日志/持久化规则交叉核对。
- **校验范围是当前 `audit.path` 指向的单个文件**。超过 `max_size_mb` 后文件会轮转为
  `audit.log.1`~`audit.log.3`，新文件的链头 `prev_hash` 指向旧文件；对**新文件单独校验会报
  链头不一致**。因此建议：调大 `max_size_mb` 减少轮转；在轮转前完成校验并归档已校验片段；
  对归档片段做只读保存（`chattr +a` 或单独备份）。
- 早期版本（v0.5.0 之前）写入的旧记录没有 hash 字段，校验时会跳过并重新起链，
  这类历史片段无法追溯校验。

## 可观测性：map 水位与告警（v0.5.0）

`eBPF map` 使用 LRU 策略：写入超过容量后会淘汰旧条目（黑名单/信誉被挤掉，防护效果下降）。
v0.5.0 新增水位观测：

```bash
# 每个 map 的条目数/上限/使用率（0.8 为告警阈值）
curl -s -H "Authorization: Bearer $TOKEN" http://<host>:8720/api/map-usage | jq
```

```json
{
  "maps": [
    {"name": "BLACKLIST", "type": "LruHashMap", "entries": 12000, "max": 100000, "ratio": 0.12},
    {"name": "RATE_MAP", "type": "LruHashMap", "entries": 18100, "max": 100000, "ratio": 0.181}
  ],
  "warn_threshold": 0.8,
  "sampled_ns": 1761234567890000000
}
```

- 数据来自后台采样缓存（`metrics_interval_s`，默认 30s），不是实时遍历；
- Array/RingBuf/LPM 表没有条目数采样，`entries` 固定为 0，水位无意义；
- Prometheus 侧：`eshield_map_usage_ratio{name="..."}`、`eshield_map_entries{...}`、
  `eshield_map_max_entries{...}`。

Prometheus 告警规则示例：

```yaml
groups:
  - name: eshield
    rules:
      - alert: EShieldMapUsageHigh
        expr: eshield_map_usage_ratio > 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "eShield map {{ $labels.name }} 使用率 {{ $value | humanizePercentage }}"
          description: "LRU 表接近容量，旧条目会被淘汰；检查误封量与阈值，必要时扩容。"

      - alert: EShieldMapUsageCritical
        expr: eshield_map_usage_ratio > 0.95
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "eShield map {{ $labels.name }} 即将打满（{{ $value | humanizePercentage }}）"

      - alert: EShieldFragmentBlocked
        expr: rate(eshield_fragment_blocked_total[5m]) > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "分片策略持续命中（policy={{ $labels.policy }}），确认是否为分片攻击或业务 MTU 异常"

      - alert: EShieldPortRateBlocked
        expr: rate(eshield_port_rate_blocked_total[5m]) > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "端口聚合限速持续命中，可能有伪造源 Flood 或阈值误伤业务"
```

补充：

- `eshield_map_max_entries` 在启动时采集；`eshield_map_usage_ratio` 依赖 30s 采样，告警用
  `for: 5m/10m` 避免抖动。
- `/ready` 不是 Prometheus 指标，请用探针（blackbox exporter / 外部拨测）抓取
  `GET /ready`，非 200 立即告警。
- 水位高的常见原因与处置：`BLACKLIST` 涨 → 误封或自适应过于激进（考虑 `soft` 模式、
  调大 `threshold`）；`RATE_MAP` 涨 → 伪造源 IP 攻击（确认 `port_rate_blocked` 是否增长）；
  `TRUST_MAP` 涨 → 来源 IP 过于分散（可关闭 `[trust_score]`）。

## 低内存启动行为（v0.5.0）

新增启动内存预检（在加载 eBPF 之前执行）：

```toml
[limits]
min_memory_mb = 512      # 低于该值：打印告警，继续启动
refuse_memory_mb = 256   # 低于该值：拒绝启动
```

- 低于 `refuse_memory_mb`：进程退出并输出
  `系统内存 xxxMB 低于 [limits].refuse_memory_mb=256MB，拒绝启动；如确需在低内存环境运行，
  设置 ESHIELD_ALLOW_LOW_MEMORY=1 强制启动（建议同时下调 map 规模或关闭部分模块）`；
- 低于 `min_memory_mb`：打印告警后继续启动；
- **不建议**使用强制启动开关：

```bash
# 仅在明确知道后果（400MB 实例装 nginx + eShield 后 sshd 会失联）时使用
sudo ESHIELD_ALLOW_LOW_MEMORY=1 systemctl start eshield   # 不推荐
```

`eshield check` 只校验配置语法与取值，不执行内存预检；内存预检发生在 `eshield start` 时。
内存占用构成见 [capacity-planning.md](capacity-planning.md) 第 6 节。

## 日志

默认输出到 journald：

```bash
sudo journalctl -u eshield -f
```

可开启 JSON 结构化日志以便对接 ELK/Loki：

```toml
log_json = true
log_level = "info"   # trace / debug / info / warn / error
```

## 告警 Webhook

```toml
alert_webhook_url = "https://hooks.slack.com/services/xxx"
alert_webhook_type = "slack"   # generic / slack / dingtalk / wecom
alert_threshold_dps = 1000     # 每秒 DROP 包数超过该值触发
alert_cooldown_s = 60          # 两条告警之间的最小间隔
```

## 备份与恢复

```bash
# 备份配置、动态规则库与审计日志
sudo tar czf eshield-backup.tar.gz /etc/eshield /var/lib/eshield /var/log/eshield

# 恢复
sudo tar xzf eshield-backup.tar.gz -C /

# 安装升级产生的备份（二进制/配置/systemd 单元）
ls -1dt /var/lib/eshield/backup/*/
```

## 故障排查

| 现象 | 排查 |
|---|---|
| `/ready` 返回 503 | XDP 未挂载（防护裸奔）：查日志 `XDP 自动重挂失败`、网卡是否存在、capability 是否齐全；必要时重启进程 |
| 升级后版本没变 | `curl -s 127.0.0.1:8720/api/config \| jq -r .version`；确认安装的是哪个二进制（`which eshield`）、服务是否重启 |
| 回滚失败/找不到备份 | 备份在 `/var/lib/eshield/backup/<时间戳>/`；确认 `--rollback <dir>` 指向存在 `eshield` 二进制的目录 |
| 卸载后配置还在 | 默认行为（`--uninstall` 保留配置与数据）；彻底删除需 `--purge` |
| 写 API 返回 403 | 使用的是 `readonly_token`；写操作请用 `api_token` |
| `/api/audit/verify` 返回 ok=false | 审计文件被改写/截断/轮转；对照 `first_bad_seq` 与备份；轮转后新文件单独校验属预期 |
| map 使用率 > 0.8 | 见「可观测性：map 水位与告警」：调阈值、soft 模式、关闭 trust，必要时扩容 |
| 启动被拒绝（内存） | 触发 `[limits].refuse_memory_mb`；加内存/关模块/降负载，不要随便用 `ESHIELD_ALLOW_LOW_MEMORY` |
| XDP 挂载失败 | 检查内核版本、BTF、capability；virtio_net 上 `rx-gro-hw: [fixed]` 时只能 generic |
| 流量未按预期 DROP | 检查白名单是否覆盖、规则优先级；用 `/api/audit` 与 `/api/stats` 确认命中来源 |
| 日志无 eBPF 事件 | 确认 `ebpf_log_enabled = true` 且内核支持 perf event |
| Dashboard 无法访问 | 检查防火墙与 `web_bind`；确认 TLS 反代已配置（默认明文 HTTP + Token） |
| Hub 连接失败 | 检查节点 `[hub]` token/url；确认 Hub 可达；查看 `/api/hub/status` |
| 策略未同步 | 检查 `sync_pull_interval_s` / `sync_push_interval_s`；确认 `push_min_hit_count` 阈值 |
| 节点被封禁自己的策略 | 确认 `node_name` 在集群内唯一；Hub 会跳过来源为本节点的策略 |

## 分布式 Hub 运维

### 查看节点连接状态

```bash
# 节点侧
eshield status --endpoint http://node:8720
# 或
curl -H "Authorization: Bearer <node_token>" http://node:8720/api/hub/status
```

### 手动触发同步

```bash
# Hub 侧查看策略
curl -H "Authorization: Bearer <hub_token>" \
  'http://hub:9930/api/v1/policies?since=0&limit=100'

# 节点侧查看 Hub 代理
curl -H "Authorization: Bearer <node_token>" \
  'http://node:8720/api/hub/proxy/policies?since=0&limit=100'
```

### 备份 Hub 数据

```bash
sudo tar czf eshield-hub-backup.tar.gz /var/lib/eshield-hub
```

> Hub 是单实例有状态服务，不是高可用组件：请定期备份，并在变更/升级前先备份。

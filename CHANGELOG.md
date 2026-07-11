# Changelog

## 0.3.4 (2026-07-11)

### 修复

- **协议维度丢包统计与全局计数不一致**：在 eBPF `GlobalStats` 中新增 `tcp_dropped` / `udp_dropped` / `icmp_dropped` / `other_dropped` 计数器，所有 DROP 路径按协议直接累加，用户态每秒从 Per-CPU map 同步，避免依赖 RingBuf 事件导致的 `tcp_dropped` / `top_ports` 与 `total_dropped` 量级不匹配。
- **Ring Buffer stale 事件残留**：将启动 drain 时机提前到 XDP 挂载之前，杜绝挂载瞬间产生的事件被误判为残留事件；同时确保 `program_start_ns` 在数据面启动前已写入。

### 改进

- **eBPF 代码去重**：提取 `rate_counter.rs`（共享速率衰减逻辑）和 `blacklist.rs::add_to_blacklist`（共享黑名单插入），四个 flood 模块不再各自复制相同逻辑。
- **纯函数提取与单元测试**：新增 `eshield-common/src/pure.rs`，将 `build_cookie`、`checksum`、`tcp_checksum`、`decay_counter`、`match_port_acl_entry`、`mix`、`mss_to_idx` 等无 eBPF 依赖的纯函数提取出来，并编写 20 个单元测试覆盖校验和、Cookie 构造、速率衰减、ACL 匹配逻辑。
- **优雅退出（XDP 卸载）**：保存 `xdp_link_id`，SIGTERM/SIGINT 时显式 `xdp.detach()` 卸载 XDP 程序，避免遗留悬空钩子。
- **时间函数统一**：新增 `eshield/src/time.rs`，所有写入 eBPF map 的时间戳统一使用 `CLOCK_MONOTONIC`；告警等 wall-clock 场景保留 `SystemTime` 并添加注释说明。
- **`BLOCK_PERMANENT` 常量**：消除 `blocked_until_ns == 0` 语义歧义。
- **审计日志文件持久化**：新增 `FileAuditBackend`，支持 JSON Lines 格式 + 自动轮转；新增 `[audit]` 配置段。
- **API 错误格式统一**：所有 API 端点错误统一返回 `{"error":"..."}` JSON 格式。
- **install.sh 改进**：版本号从 `Cargo.toml` 自动解析；service 路径修正为 `packaging/eshield.service`；默认白名单与 `config.example.toml` 对齐。
- **Token 日志安全**：自动生成的访问令牌仅打印前 8 位前缀且降级为 `warn`。
- **Dashboard ECharts 离线化**：ECharts 库嵌入二进制，不再依赖外部 CDN。
- **Dashboard HTML 转义**：所有用户/服务端数据在 `innerHTML` 渲染前经过 `escHtml()` 转义，防止 XSS。
- **审计日志服务端过滤**：`/api/audit` 新增 `filter` 查询参数，支持服务端全文过滤与分页。
- **HTTP 请求日志中间件**：记录 method、path、status、耗时、客户端 IP。
- **请求体大小限制**：超过 1 MiB 的请求返回 413 Payload Too Large。
- **TUI 异步化**：`reqwest::blocking` 替换为异步 `reqwest::Client`。
- **`/ready` 端点**：真实检查 eBPF 程序是否已加载，而非空返回。
- **Dashboard 导航优化**：合并冗余页面，侧边栏从 6 页精简为 4 页分类（监控/防护/安全运营/系统）。

## 0.3.3 (2026-07-07)

### 修复

- **事件消费高 CPU / 统计不一致**：SYN Flood / UDP Flood / ICMP Flood / rate_limit / blacklist 等高频率 DROP 路径不再写入 RingBuf，避免海量事件 backlog 占满单核并导致 `total_dropped` 与 `top_attackers` 量级不一致。
- **黑名单拦截计数失真**：新增 `GlobalStats.blacklist_blocked`，由 eBPF 数据面直接累加，不再依赖 RingBuf 事件。

### 改进

- **TOP 攻击源实时同步**：用户态新增后台任务，每秒从 eBPF `BLACKLIST` map 读取 `BlockEntry.hit_count` 重建 `top_attackers`，来源统计与全局丢包计数保持同步。

---

## 0.3.2 (2026-07-07)

### 修复

- **Dashboard 登录后仍被重定向**：登录接口现在写入 `eshield-token` Cookie，认证中间件同时支持 `Authorization: Bearer <token>` 和 `Cookie: eshield-token=<token>`，解决控制台输入 Token 后仍停留在登录页的问题。
- **事件消费高 CPU**：SYN Flood / UDP Flood / ICMP Flood / L7 / BLACKLIST / GEOIP 事件不再进入自适应引擎，避免海量事件反复操作 DashMap 占满 CPU。
- **启动统计被旧事件污染**：Ring Buffer 残留 stale 事件 drain 上限从 100 万提高到 5000 万，防止前一次测试的巨量事件污染新进程统计。

### 改进

- `.sync_remote.py` 支持 SSH 私钥认证，优先使用 `~/.ssh/id_ed25519` 等常见私钥，不再强制依赖 `.remote_pass`。

---

## 0.3.1 (2026-06-20)

### 重大变更

- **移除 WAF 与 Challenge 模块**：项目重新聚焦网络层 DDoS 清洗，不再内置 HTTP WAF 与 JS Challenge 能力，以降低 eBPF verifier 压力和代码复杂度。

### 新增

- **TCP RST 回包**：丢弃 TCP 连接时可选立即回复 RST，避免客户端持续重传。
- **RST 诊断计数器**：`tcp_rst_sent` / `tcp_rst_fail` / `tcp_rst_attempt` 统计并同步到 `/api/stats`。
- **eBPF 全局统计同步**：`total_packets`、`total_dropped`、`total_passed` 以及各分类计数改由 eBPF Per-CPU `GLOBAL_STATS` 每秒同步到用户态，避免 Ring Buffer 事件丢失/重复导致的统计失真。
- **Ring Buffer 防污染**：启动时 drain 残留事件，并基于 `CLOCK_MONOTONIC` 时间戳过滤 stale 事件。
- **控制台侧边栏重组**：分为“统计 / 防护项目 / 防护策略 / 攻击日志 / 系统”五个分组。
- **控制台动态卡片**：总览页指标数字增加计数动画、涨跌箭头、实时呼吸灯和 30 点 Sparkline 趋势图。
- **认证与令牌管理**：CLI 支持 `reset-token`，控制台登录页支持防暴力破解。
- **集成测试增强**：新增 `tests/full_attack_test.sh`，覆盖 UDP/ICMP/SYN Flood 完整攻防场景。

### 改进

- 优化事件消费器 CPU 占用：批量消费 + 批间 sleep，避免饿死 Web/API。
- 调整自适应引擎触发逻辑，仅在启用时处理事件并扩大消费批量。
- 隐藏控制台侧边栏滚动条，保持可滚动但视觉更干净。
- 同步重写中文/英文 README，移除 WAF/Challenge 描述，补充攻击者成本分析。

### 修复

- 修复 Port ACL dport 字节序读取问题。
- 修复 WAF DROP 路径未回 RST 的问题（后续随 WAF 整体移除）。
- 修复 `GLOBAL_STATS` 从 PerCpuArray 用户态读取丢失 CPU 值的问题。

---

## 0.2.0

- 初始完整功能版本：eBPF/XDP 数据面、Rust 控制面、Dashboard、CLI、TUI、审计日志、GeoIP、威胁情报、自适应阈值、防护项目分组等。

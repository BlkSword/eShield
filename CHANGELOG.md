# Changelog

## Unreleased (0.4.6)

### 修复

- **SYN Cookie 代理恢复（降级式挑战）**：v0.4.2 因 eBPF verifier 兼容问题被临时禁用（`handle_syn`/`handle_ack` 空实现），现恢复为 Katran 式降级挑战——SYN Flood 超限源进入 Cookie 挑战模式（XDP_TX 回 SYN-ACK，伪造源无法通过验证，在 XDP 层被清洗），合法客户端响应 Cookie 后自动解除挑战、后续连接直通内核正常握手；未触发阈值的正常连接始终无感直通。「防护策略」页的 SYN Proxy 开关现在真实生效。
- **防护项目数据面落地**：新增 `PROJECT_POLICY` map，target_ips 的 CIDR 由控制面展开为精确 IP（下限 /24，`eshield check` 阶段校验）后下发；PASS/DROP 在数据面真实生效（支持 any 端口/协议通配），DEFEND 复用全局防御模块；IPv6 目标暂不匹配（控制面跳过并记录日志）。
- 移除旧版单文件控制台：`/legacy` 路由、`dashboard.html` 嵌入与 `tests/remote/console_verify.sh` 中对应检查。
- 删除未使用的 eBPF Map（`RULE_HITS`、`SYN_PROXY_CONN`）；清理 `sync_trust_scores` 中自存自读的 `danger_level` 残留代码。
- `port_acl.rs` 双重匹配去重（热路径少一次重复判断，统一由 `match_port_acl_entry` 判定）。

### 改进

- Trust Score 分布同步由每秒降频为每 5 秒（TRUST_MAP 最多 10 万条，降低全局 Ebpf 锁占用）。
- 自适应引擎滑动窗口改用 `CLOCK_MONOTONIC`（原 `SystemTime`，避免 NTP 校时导致窗口错乱）。
- GeoIP LPM Trie 容量预警：IPv4/IPv6 条目达到上限 80% 时输出告警日志。
- 文档同步：ROADMAP 标注 WAF/Challenge 已于 v0.3.4 移除、SYN Cookie 与防护项目状态；修正 `config.rs` 中 Hub 配置注释版本号。

## 0.4.5 (2026-07-18)

### 新增

- **控制台全面重写**：新控制台位于 `eshield/web/`，原生 ES modules + 模块化 CSS，无前端构建链，仍全部嵌入单二进制。
  - 暗色优先 SOC 视觉体系（完整 design tokens，暗/亮双主题），统一 SVG 线性图标，替换 emoji。
  - 九个页面：总览 / 攻击事件 / 包日志 / 审计日志 / 防护策略 / 规则中心 / 安全运营 / 集群节点 / 设置。
  - 总览页：6 张 KPI 卡（sparkline + 模块状态点）、按防御模块分解的趋势图（折线/堆叠 + 15分钟~24小时四档）、实时拦截事件流、协议分布环图、TOP 端口、TOP 攻击源。
  - 全局 IP 搜索（`/` 聚焦，Enter 直达 IP 情报抽屉）；IP 情报抽屉展示信誉分、采样包、端口分布与攻击趋势，可直接封禁/解封。
  - 审计日志页：服务端过滤 + 真分页 + SSE 实时插入 + CSV 导出。
  - 防护策略页：模块开关即改即存，参数表单保存完整子对象；防护项目可视化管理。
  - 骨架屏 / 空态 / 错误态三态统一；轮询随页面切换自动启停。
  - 旧版单文件控制台保留在 `/legacy`，将于下个版本移除。
  - 新增 `tests/remote/console_verify.sh` 端到端验证（27 项检查）。
- **TOP 攻击源趋势**：攻击事件页新增 TOP5 攻击源趋势折叠卡片，调用既有 `GET /api/metrics/attacker-series`，按时间范围（与总览趋势联动）绘制逐间隔丢包数多线图，10s 轮询随页面卸载停止。

### 修复

- **Ring Buffer 幻影事件（严重）**：`event_consumer` 与 `packet_log` 每批事件都重建 aya `RingBuf` 句柄，aya 的 `pos_cache` 初值为 0，consumer 位置越过 producer 后已消费事件被无限重读——空流量下持续读出 4096 条/批的旧事件，CPU 占满一个核，并拖慢 Hub 策略上报。现改为启动时 `take_map` 取出 map 所有权、RingBuf 句柄随消费任务常驻；`packet_log` 消费不再需要 Ebpf 锁。
- **趋势图 X 轴标签重复**：采样间隔 <60s 时标签降级为 `HH:MM:SS`；`categoryAxis` 启用 `hideOverlap` 自动抽稀。
- **趋势图 legend 与 Y 轴刻度重叠**：legend 改为单行滚动（`type: 'scroll'`），grid top 从 34 提升到 40。
- **feed 卡片头部拥挤**：`.card-head` 增加 `flex-wrap: wrap`，窄宽度下工具区自动换行。

- **攻击事件 / 包日志时间戳错误**：`/api/attack-events` 与 `/api/packets` 返回的 eBPF 单调时钟纳秒未转换为 wall-clock，前端显示为"1970 + 开机时长"；后端现统一转换后返回。
- **reset-token 后 SSE 断流**：`POST /api/auth/reset-token` 现在同步 `Set-Cookie`，EventSource（仅可携带 cookie）不再因旧令牌失效而 401。
- **保存速率限制参数强制开启开关**：新防护策略页以当前 config 快照为底叠上表单值提交完整子对象，不再硬编码 `enabled: true`。
- **审计页 SSE 状态标签失效**：新版消除了重复的 `id="sse-status"`，SSE 三态（已连接/连接中/重连中）全局可见。
- 清理旧控制台死代码：未使用的防护模块 modal、`attackerChart`、未实现的"全局搜索"注释。

### 改进

- 版本号显示改为读取后端 `/api/config` 的 `version` 字段，不再使用硬编码 fallback。

## 0.4.2 (2026-07-12)

### 新增

- **分布式 Hub-Node 协同免疫**：新增 `eshield-hub` 二进制，作为策略聚合中心。
  - 节点通过 `[hub]` 配置上报本地黑名单/Trust Score 到 Hub。
  - 节点从 Hub 拉取其他节点策略与 Hub 威胁情报，实现跨节点共享免疫记忆。
  - Hub 端点：`/api/v1/policies`、`/api/v1/policies/deleted`、`/api/v1/rules`、`/api/v1/nodes`、`/api/v1/stats`。
  - 节点端代理：`/api/hub/status`、`/api/hub/proxy/*`。
- **规则包统一下发**：Hub 可统一下发端口 ACL、L7 指纹、防护项目到所有节点。
- **tombstone 删除同步**：Hub DELETE 策略后生成墓碑记录，节点拉取后自动解封。
- **多 Hub URL 故障转移**：节点 `urls` 支持配置多个 Hub 地址，失败自动轮询切换。
- **Hub Dashboard**：独立 Web 页面展示在线节点、聚合策略、全局统计。
- **节点集群页面**：节点 Dashboard 新增「集群节点」卡片，展示本节点到 Hub 的连接状态与在线节点列表。
- **Hub TLS 支持**：Hub 可自带 rustls；节点侧 reqwest 支持 CA、客户端证书、跳过校验。
- **Hub 威胁情报 feed**：Hub 可统一拉取外部 feed 后分发给各节点。
- **集成测试**：新增 `tests/hub_node_test.sh`，覆盖节点上线、心跳、策略上报、peer 策略拉取/封锁、Hub 删除解封、规则同步、Dashboard。

### 修复

- 修复 BlacklistSync 覆盖 Hub 策略来源的问题，确保 Hub DELETE 后能正确解封。
- 修复节点应用 Hub 策略时回传本节点策略导致的永久封禁问题：现在会跳过 `source_nodes` 包含本节点名的策略。
- 修复 `tests/hub_node_test.sh` 跨测试 store 污染问题，启动时清理上次失败的持久化数据。

### 改进

- `packaging/config.example.toml` 补充完整 `[hub]` 配置示例（含 `sync_rules_enabled`、`sync_rules_interval_s`、`tls`）。
- 文档更新：`README.md`、`README_EN.md`、`docs/distributed-architecture.md`、`docs/deployment.md`、`docs/operations.md`、`docs/api.md`、`docs/development-plan.md`、`ROADMAP.md` 同步反映 v0.4.2 分布式能力。

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

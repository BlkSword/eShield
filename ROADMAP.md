# eShield 路线图（Roadmap）

> 当前版本：**v0.3.0**（已发布）
>
> 已完成：单节点 CC/DDoS 防御组件的**现代化控制台、实时流量趋势、规则编辑器、规则持久化**。
>
> 当前焦点：**v0.3.1 — 控制台视觉升级与产品化收尾**

---

## 已完成的阶段

### v0.1 — 基础数据面

- [x] eBPF/XDP 包解析与 DROP/PASS 决策
- [x] CIDR 白名单（LPM Trie，IPv4/IPv6）
- [x] 动态黑名单（LRU HashMap，到期自动解封）
- [x] Per-IP 指数衰减速率限制
- [x] SYN Cookie 代理 / SYN Flood 检测
- [x] L7 轻量指纹扫描（TCP 载荷前 64 字节）
- [x] 自适应阈值引擎
- [x] Ring Buffer 事件上报

### v0.2 — 实时控制与可观测性

- [x] RESTful 控制 API（封禁/解封、白名单、配置补丁、热加载）
- [x] 中文 Web Dashboard 控制表单
- [x] CLI 实时控制子命令（`block` / `unblock` / `reload` / `status` / `check` / `tui`）
- [x] 按规则维度与源 IP 的 Prometheus 指标
- [x] 中文 TUI 仪表盘
- [x] SIGHUP / `systemctl reload` 热加载
- [x] 配置校验与 dry-run：`eshield check --config`
- [x] eBPF 内核调试日志（`AYA_LOGS`）与运行时开关
- [x] 本地 fmt/clippy 与远程 Linux 集成测试全部通过

### v0.2.0 — 高级 L7 与有状态代理（已发布）

- [x] 有状态 SYN Proxy / SYN Cookie，支持 TCP MSS 选项协商
- [x] HTTP WAF 规则引擎（method / path_prefix / host / user_agent / body_prefix 多维度匹配）
- [x] WAF 动作：drop / log / challenge
- [x] JS/302 Challenge 模式，验证通过后自动加入临时白名单
- [x] GeoIP/ASN CIDR 过滤（自定义 CSV + MaxMind MMDB）
- [x] 威胁情报联动（文本/CSV/JSON feed，支持 AbuseIPDB / CINS / 自定义 URL）
- [x] Dashboard 扩展：WAF、GeoIP、威胁情报、Challenge 配置展示
- [x] 规则持久化迁移到 redb，启动时跳过历史 `BLACKLIST` 避免覆盖配置文件
- [x] 扩展集成测试：Test 4.5（WAF）、Test 4.6（Challenge）、Test 8（GeoIP）、Test 9（威胁情报）

---

## v0.3.0 — 已发布

**目标**：现代化控制台与实时数据增强。

- [x] 时间序列指标窗口与 `/api/metrics/series` API
- [x] `/api/stats` 扩展 PPS/DPS
- [x] Dashboard 侧边栏导航、暗黑/亮色主题、响应式布局
- [x] Dashboard 实时流量趋势图（ECharts）
- [x] IP 情报抽屉
- [x] WAF / Port ACL / L7 指纹规则编辑器（实时生效 + 持久化）
- [x] GeoIP 重新加载、威胁情报手动同步
- [x] RuleStore 扩展支持 WAF/Port ACL/L7 规则持久化
- [x] 编译 warning 清零
- [x] 新增 `CHANGELOG.md`

## 下一阶段：v0.3.1 — 控制台视觉升级与产品化收尾

**目标**：参考专业安全产品（如雷池 WAF）的视觉与交互，进一步打磨控制台美感；补齐单节点交付所需的运维与测试能力。

### 1. 控制台视觉升级

- [ ] 参考雷池 WAF 重新设计 Dashboard 视觉风格（更清爽的配色、更专业的图标、更合理的留白）
- [ ] 替换 emoji 为统一 SVG 图标
- [ ] 优化字体、字号、行距与视觉层级
- [ ] 统一卡片、表格、按钮、表单样式
- [ ] 增加页面切换动画与微交互

### 2. 控制台体验增强

- [ ] TOP 攻击源趋势（历史曲线）
- [ ] 审计事件流 / SSE 实时滚动
- [ ] 按 IP / 动作 / 时间过滤审计日志
- [ ] 紧急封禁的移动端快捷操作

### 3. 可观测性与告警

- [ ] 增强 Prometheus 指标（按接口/协议/端口细分、包处理耗时直方图、eBPF Map 使用率）
- [ ] 告警 Webhook（Slack / 钉钉 / 企业微信 / 自定义 HTTP）
- [ ] 结构化日志统一字段：`event_type`, `src_ip`, `dst_port`, `rule`, `action`, `reason`

### 4. 运维与交付

- [ ] 权限最小化（加载 eBPF 后 drop root，保留必要 capabilities）
- [ ] 优雅退出（SIGTERM 卸载 XDP、清理 eBPF Map）
- [ ] DEB / RPM 安装包（`cargo deb` / `cargo generate-rpm`）
- [ ] 最小容器镜像 + Docker Compose + Kubernetes DaemonSet 示例
- [ ] 完善 `docs/deployment.md` 与 `docs/ops.md`
- [ ] GitHub Release 发布脚本

### 5. 测试与质量

- [ ] 单元测试覆盖核心模块（`parser`、`syn_cookie`、`rate_limit`、`config`）
- [ ] 属性测试：随机生成畸形包、非法 CIDR、边界阈值
- [ ] 负向集成测试：放行流量可达、白名单不误杀
- [ ] IPv6 / UDP / ICMP 集成测试扩展
- [ ] 性能回归 CI（PPS 基线，下降 >5% 告警）
- [ ] Verifier 矩阵测试（5.10 / 5.15 / 6.1 / 6.8）

---

## 远期：v1.0 — 分布式与云原生

目标：从单机工具演进为可水平扩展的防护体系。

- [ ] **集中式控制器（eShield Controller）**
  - 多节点 eShield 上报事件与指标
  - 控制器统一下发黑白名单、策略、阈值
- [ ] **集群同步**
  - 基于 Raft / gossip 在节点间同步黑名单
  - 支持标签、Region、机房维度分组策略
- [ ] **Kubernetes Operator**
  - 通过 CRD 定义防护策略
  - DaemonSet 形式部署在每个 Node 上，自动挂载主机网卡
- [ ] **流量镜像与分析**
  - 可选将可疑流量采样导出到 Kafka / ClickHouse 做离线分析
- [ ] **自动化应急响应**
  - 基于 Prometheus Alertmanager 联动，触发自动封禁
  - 与 Slack / 钉钉 / 企业微信等告警通道集成

---

## 建议的推进顺序

如果希望最快交付一个“完整可用”的单节点产品，建议按以下顺序：

1. **工程清理**（warning、CHANGELOG、文档）
2. **Dashboard 实时图表 + TOP 攻击源趋势**（控制台体验质变）
3. **统一规则引擎 + RuleGroup**（策略管理质变）
4. **打包交付**（DEB/RPM/容器/systemd）
5. **告警 Webhook + 增强指标**（可运营）
6. **分布式控制器**（v1.0）

---

## 贡献与拆分手册

- 每个阶段独立一个 milestone。
- 每个功能点保持“单 PR 可 review、可测试、可回滚”。
- 涉及 eBPF 数据面改动的，必须同步更新 `tests/netns_test.sh`。
- 新增配置项需要同时更新：
  - `packaging/config.example.toml`
  - `README.md`
  - `docs/architecture.md`
  - `docs/deployment.md`（如需要）

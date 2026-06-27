# eShield 路线图（Roadmap）

> 当前版本：**v0.2.0**（已发布）
>
> 已完成：从“单节点主机防护工具”演进为具备 **有状态代理、L7 WAF、Challenge、GeoIP/ASN、威胁情报联动** 的生产级 CC / DDoS 防御组件。
>
> 当前焦点：**v0.3.0 — 产品化打磨与运维交付**

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

## 下一阶段：v0.3.0 — 产品化打磨与运维交付

**目标**：让 eShield 在单节点场景下**控制台更完整、交付更标准、可长期稳定运行**，达到可直接交给运维团队的水平。

### 1. 控制台体验增强

| 功能 | 说明 | 优先级 |
|---|---|---|
| **实时图表** | Dashboard 展示 PPS/DPS/各规则命中数曲线（1h / 6h / 24h） | P0 |
| **TOP 攻击源趋势** | 动态排行 + 历史趋势 | P0 |
| **IP 情报卡片** | 点击攻击源 IP 展示命中次数、最近事件、GeoIP/ASN、当前状态 | P1 |
| **审计与事件流** | 实时滚动显示 DROP / PASS / 控制操作日志，支持按 IP/规则/时间过滤 | P1 |
| **移动端适配** | 响应式布局，支持紧急封禁 | P2 |

### 2. 规则引擎升级

让策略从“单一维度”升级为“组合规则”。

- [ ] **统一 Rule 对象**
  - 字段：名称、优先级、匹配条件、动作（PASS / DROP / LOG / CHALLENGE）、生效时间窗口
- [ ] **多维匹配条件**
  - 源 IP / CIDR
  - 目的端口 / 端口段
  - 协议（TCP/UDP/ICMP）
  - 国家 / ASN
  - L7 指纹（前缀 / 包含 / 正则子集）
- [ ] **规则组（RuleGroup）**
  - 命名 IP/CIDR 组，如 `internal_office`、`cdn_nodes`，在规则中引用
- [ ] **默认策略与兜底动作**
  - 明确配置 `default_action = "pass" | "drop"`
- [ ] **规则冲突解析**
  - 白名单始终最高优；同优先级按“最具体匹配”胜出

### 3. 可观测性与告警

- [ ] **增强指标**
  - 按接口、协议、目的端口细分
  - 包处理耗时直方图（`eshield_packet_process_duration_seconds_bucket`）
  - eBPF Map 使用率（`eshield_map_entries` / `eshield_map_capacity`）
- [ ] **告警 Webhook**
  - 当 DROP 速率、TOP 攻击源、错误数超过阈值时触发
  - 支持 Slack / 钉钉 / 企业微信 / 自定义 HTTP
- [ ] **结构化日志增强**
  - 统一字段：`event_type`, `src_ip`, `dst_port`, `rule`, `action`, `reason`
  - 更方便对接 ELK / Loki

### 4. 运维与交付

- [ ] **权限最小化**
  - 加载 eBPF 后 drop root，仅保留必要 capabilities
  - 提供 systemd `AmbientCapabilities` 示例
- [ ] **优雅退出**
  - SIGTERM 时安全卸载 XDP 程序，清理 eBPF Map
  - 避免网卡残留导致流量黑洞
- [ ] **DEB / RPM 安装包**
  - `cargo deb` / `cargo generate-rpm`
  - 自动创建 `/etc/eshield/` 与 systemd service
- [ ] **容器镜像**
  - 基于 `gcr.io/distroless/static` 的最小镜像
  - 提供 Docker Compose 与 Kubernetes DaemonSet 示例
- [ ] **Ansible / Terraform 示例**
  - 一键在云主机上部署并配置安全组
- [ ] **升级路径**
  - 保留配置文件与动态规则库，滚动升级不丢策略

### 5. 测试与质量

- [ ] **单元测试覆盖**
  - 目标核心模块覆盖率达 70%+
  - 为 `parser`、`syn_cookie`、`rate_limit`、`config` 增加测试
- [ ] **属性测试（Property-based）**
  - 随机生成畸形包、非法 CIDR、边界阈值验证数据面鲁棒性
- [ ] **负向集成测试**
  - 验证“放行流量必须可达”、“误杀白名单 IP 会失败”
- [ ] **IPv6 / UDP / ICMP 集成测试**
  - 扩展 `tests/netns_test.sh` 覆盖新增协议
- [ ] **性能回归 CI**
  - 每次 PR 记录 PPS 基线，下降超过 5% 自动告警
- [ ] **Verifier 压力测试**
  - 在 5.10 / 5.15 / 6.1 / 6.8 内核矩阵上验证 eBPF 加载

### 6. 工程清理

- [ ] 清理当前编译 warning（未使用导入、字段、常量）
- [ ] 新增 `CHANGELOG.md`
- [ ] 完善 `docs/deployment.md` 与 `docs/ops.md`
- [ ] GitHub Release 发布脚本

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

# eShield 路线图（Roadmap）

> 当前版本：**v0.1.2-dev** — 已实现实时控制 API、中文 Web Dashboard、CLI 控制、按规则维度指标、eBPF 调试日志开关、配置校验与 control/state 单元测试。
>
> 目标：从“单节点主机防护工具”演进为**功能完整、可运营、可集中管理的生产级 CC / DDoS 防御组件**。

---

## 已完成的阶段

### v0.1 — 基础数据面

- [x] eBPF/XDP 包解析与 DROP/PASS 决策
- [x] CIDR 白名单（LPM Trie）
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
- [x] `control.rs` / `state.rs` 单元测试
- [x] 本地 fmt/clippy 与远程 Linux 集成测试全部通过

---

## 下一阶段：v0.1.2 — 生产级单节点完整方案

**目标**：让 eShield 在单节点场景下**功能完整、控制台完全可控、可长期稳定运行**，达到可直接交付运维团队使用的水平。

### 1. 网络协议与场景补全

| 功能 | 说明 | 优先级 |
|---|---|---|
| **IPv6 全链路支持** | 解析 IPv6 头部；白名单/黑名单/速率限制/SYN Flood/L7 扫描均支持 128-bit key；CLI 与配置支持 IPv6 CIDR。 | P0 |
| **UDP Flood 防护** | 对 UDP 源 IP 做 Per-CPU / Per-IP 速率限制，超过阈值 DROP。 | P1 |
| **ICMP Flood 防护** | 对 ICMP Echo Request 做源 IP 速率限制，可选全局抑制。 | P1 |
| **双栈自动识别** | 同一条规则可同时作用于 IPv4 与 IPv6，配置写法保持一致。 | P1 |
| **端口级 ACL** | 支持按源/目的端口放行或封禁（如仅开放 80/443，其余 DROP）。 | P1 |
| **协议级规则** | 按 TCP/UDP/ICMP 等协议单独配置策略。 | P2 |

### 2. 规则引擎（Rule Engine）

让策略从“单一维度”升级为“组合规则”。

- [ ] **规则对象化**
  - 每条规则包含：名称、优先级、匹配条件、动作（PASS / DROP / LOG / CHALLENGE）、生效时间窗口。
- [ ] **多维匹配条件**
  - 源 IP / CIDR
  - 目的端口 / 端口段
  - 协议（TCP/UDP/ICMP）
  - 国家 / ASN（依赖 GeoIP）
  - L7 指纹（前缀/包含/正则子集）
- [ ] **规则组（Group）**
  - 命名 IP/CIDR 组，如 `internal_office`、`cdn_nodes`，在规则中引用。
- [ ] **默认策略与兜底动作**
  - 明确配置 `default_action = "pass" | "drop"`。
- [ ] **规则冲突解析**
  - 白名单始终最高优；同优先级按“最具体匹配”胜出。

### 3. 控制面安全与审计

- [ ] **API 认证机制**
  - API Token（默认）
  - 可选 JWT / mTLS
  - Dashboard 登录页
- [ ] **操作审计日志**
  - 持久化到 SQLite / 本地文件
  - 记录：时间、用户/Token、动作、变更前后值、来源 IP
  - Web Dashboard 审计日志查询页
- [ ] **动态规则持久化**
  - API/Web/CLI 产生的黑名单、白名单、规则变更自动落盘
  - 启动时从 SQLite 恢复，与配置文件合并
  - 支持配置回滚到上一版本
- [ ] **配置版本与 diff**
  - `PATCH /api/config` 返回变更摘要
  - 支持 `dry-run=true` 预览效果

### 4. Web 控制台 v2（完全可控）

把 Dashboard 从“查看 + 简单开关”升级为“完整的策略管理中心”。

- [ ] **实时图表**
  - 总 PPS / DPS / 各规则命中数曲线（最近 1h / 6h / 24h）
  - TOP 攻击源动态排行
- [ ] **规则编辑器**
  - 表格化增删改查规则
  - 拖拽调整优先级
  - 实时验证规则合法性
- [ ] **IP 情报卡片**
  - 点击攻击源 IP 展示：命中次数、最近事件、所属国家/ASN、当前状态
- [ ] **审计与事件流**
  - 实时滚动显示 DROP / PASS / 控制操作日志
  - 支持按 IP、规则、时间过滤
- [ ] **批量导入/导出**
  - 黑名单 CSV / JSON 导入
  - 配置与规则一键导出备份
- [ ] **移动端适配**
  - 响应式布局，支持手机查看与紧急封禁

### 5. 可观测性与告警

- [ ] **结构化日志**
  - JSON 格式可选，对接 ELK / Loki
  - 统一日志字段：`event_type`, `src_ip`, `dst_port`, `rule`, `action`, `reason`
- [ ] **增强指标**
  - 按接口、协议、目的端口细分
  - 包处理耗时直方图（`eshield_packet_process_duration_seconds_bucket`）
  - eBPF Map 使用率（`eshield_map_entries` / `eshield_map_capacity`）
- [ ] **健康检查端点**
  - `/healthz`：进程存活
  - `/ready`：eBPF 程序已挂载、接口正常
- [ ] **告警 Webhook**
  - 当 DROP 速率、TOP 攻击源、错误数超过阈值时触发
  - 支持 Slack / 钉钉 / 企业微信 / 自定义 HTTP

### 6. 运维与交付

- [ ] **权限最小化**
  - 加载 eBPF 后 drop root，仅保留 `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_PERFMON`、`CAP_IPC_LOCK`
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

### 7. 测试与质量

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

---

## 再下一阶段：v0.2.0 — 高级 L7 与有状态代理

目标：让 SYN Cookie 代理真正保护后端 TCP 服务，并引入 WAF 级 L7 能力。

- [ ] **有状态 SYN Proxy / TCP Splicing**
  - ACK Cookie 验证通过后，向本地协议栈注入原始 SYN
  - 维护极简连接状态表，完成三次握手转发
  - 正常 TCP 业务可长期开启 SYN Proxy
- [ ] **HTTP WAF 规则引擎**
  - 支持方法、URI、Header、User-Agent、Body 前缀等多维度
  - 匹配方式：等于、前缀、后缀、包含、正则子集
  - 动作：DROP / PASS / LOG / CHALLENGE
- [ ] **挑战模式（Challenge）**
  - 对可疑 IP 返回 HTTP 302 / JS 挑战
  - 验证通过后自动加入临时白名单
- [ ] **GeoIP / ASN 过滤**
  - 集成 MaxMind GeoIP2 或 IP2Location
  - 按国家/ASN 批量放行或封禁
- [ ] **威胁情报联动**
  - 定时从公开/私有黑名单源同步恶意 IP
  - 支持 AbuseIPDB、CINS、自定义 URL

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

1. **IPv6 全链路支持**（现代网络基础能力，越早做改动越小）
2. **API 认证 + 审计日志 + 规则持久化**（控制面可安全使用）
3. **Web Dashboard v2**（完全可控的控制台）
4. **端口级 ACL + UDP/ICMP 防护**（补齐数据面能力）
5. **权限最小化 + DEB/RPM/容器镜像**（可交付运维）
6. **规则引擎 + GeoIP + 告警**（接近商业 WAF 体验）

---

## 贡献与拆分手册

- 每个阶段独立一个 milestone。
- 每个功能点保持“单 PR 可 review、可测试、可回滚”。
- 涉及 eBPF 数据面改动的，必须同步更新 `tests/netns_test.sh`。
- 新增配置项需要同时更新：
  - `packaging/config.example.toml`
  - `README.md`
  - `docs/deployment.md`（如需要）

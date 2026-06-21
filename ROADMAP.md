# eShield 路线图（Roadmap）

> 当前版本：v0.2.0-dev — 已加入实时控制 API、中文 Web Dashboard、CLI 控制与按规则维度指标。
> 本路线图按优先级与依赖关系分为四个阶段，目标是从“单节点主机防护工具”演进为“可运营的生产级 CC 防御组件”。

---

## 第一阶段：实时控制与可运维性（v0.2.x，近期）

目标：解决“只能改配置 + SIGHUP 热加载”的痛点，让运维人员可以通过 API / Web / CLI 实时调整策略。

- [x] **RESTful 控制 API**
  - `POST /api/config/reload`：触发热加载。
  - `POST /api/blacklist` / `DELETE /api/blacklist`：实时封禁/解封 IP。
  - `POST /api/whitelist` / `DELETE /api/whitelist`：实时增删白名单。
  - `PATCH /api/config`：调整速率限制阈值、tick、开关（速率限制 / SYN Proxy / L7 扫描）。
  - 注：L7 指纹规则的实时增删仍通过配置文件 + reload 完成。
- [x] **Web Dashboard 控制表单（中文界面）**
  - 在 Dashboard 增加“IP 封禁/放行”输入框与按钮。
  - 速率限制、SYN Proxy、L7 扫描的可视化开关。
  - 按规则维度展示拦截统计。
- [ ] **操作日志与审计**
  - 记录 API / Web / CLI 控制操作（谁/何时/做了什么变更）。
- [x] **CLI 实时控制子命令**
  - `eshield block <ip> --duration <s>`
  - `eshield unblock <ip>`
  - `eshield reload`
  - `eshield status`
- [ ] **配置校验与 dry-run**
  - 启动前检查 CIDR 合法性、阈值合理性、接口存在性。
  - `eshield check --config /etc/eshield/config.toml` 命令。
- [x] **更丰富的指标**
  - 按规则维度统计（`eshield_blacklist_blocked_total`、`eshield_rate_limited_total` 等）。
  - 按源 IP 细分（`eshield_source_dropped_total{ip="..."}`）。
- [ ] **高级指标**
  - 按协议、端口细分。
  - 每秒包数 / 每秒 DROP 数的 Gauge。

---

## 第二阶段：功能补全与生产加固（v0.3.x，中期）

目标：补齐 IPv6、日志、安全、多架构等企业级基础能力。

- [ ] **IPv6 支持**
  - eBPF 数据面解析 IPv6 头部。
  - 白名单/黑名单/速率限制使用 128-bit key。
  - CLI 与配置支持 IPv6 CIDR。
- [ ] **eBPF 日志集成**
  - 修复 `AYA_LOGS` 缺失警告，使用 `aya-log` 输出内核调试信息。
  - 用户态可选开启/关闭内核日志，避免高频日志冲击。
- [ ] **权限最小化**
  - 启动加载 eBPF 后 drop root，使用保留 capability 运行。
  - 可选 seccomp-bpf 沙箱。
- [ ] **多架构 Release**
  - CI 构建 x86_64 / aarch64 的 musl 静态二进制。
  - 提供 DEB / RPM 安装包。
- [ ] **真正的多内核 CI 矩阵**
  - 使用 QEMU + virtme-ng / Vagrant 在 5.10 / 5.15 / 6.1 / 6.8 等内核上运行集成测试。
- [ ] **单元测试与负向测试**
  - 为 cookie 计算、校验和、配置解析增加单元测试。
  - 构造畸形包测试 eBPF verifier 与数据面鲁棒性。

---

## 第三阶段：高级防护与连接代理（v0.4.x，中远期）

目标：让 SYN Cookie 代理能够真正保护后端 TCP 服务，同时增强 L7 能力。

- [ ] **有状态 SYN Proxy / TCP Splicing**
  - 验证 ACK Cookie 后，向本地协议栈注入（或重新构造）原始 SYN。
  - 维护极简连接状态表，完成三次握手转发，正常 TCP 业务可长期开启 SYN Proxy。
- [ ] **L7 WAF 规则引擎**
  - 支持 HTTP 方法、URI、Header、User-Agent 等多维度规则。
  - 支持字符串、前缀、后缀、包含等匹配方式。
  - 规则优先级、动作（DROP / PASS / LOG / CHALLENGE）。
- [ ] **挑战模式（Challenge）**
 - 对可疑 IP 返回 HTTP 302/JS 挑战，验证真人浏览器后自动加入白名单。
- [ ] **GeoIP / ASN 过滤**
  - 集成 MaxMind GeoIP2 或类似数据库。
  - 按国家/ASN 批量放行或封禁。

---

## 第四阶段：分布式与云原生（v1.0+，远期）

目标：从单机工具演进为可水平扩展的防护体系。

- [ ] **集中式控制器（eShield Controller）**
  - 多节点 eShield 上报事件与指标。
  - 控制器统一下发黑白名单、策略、阈值。
- [ ] **集群同步**
  - 基于 Raft / gossip 在节点间同步黑名单。
  - 支持标签、Region、机房维度分组策略。
- [ ] **Kubernetes Operator**
  - 通过 CRD 定义防护策略。
  - DaemonSet 形式部署在每个 Node 上，自动挂载主机网卡。
- [ ] **流量镜像与分析**
  - 可选将可疑流量采样导出到 Kafka / ClickHouse 做离线分析。
- [ ] **自动化应急响应**
  - 基于 Prometheus Alertmanager 联动，触发自动封禁。
  - 与 Slack / 钉钉 / 企业微信等告警通道集成。

---

## 当前建议优先做的 3 件事

1. **实时控制 API + Web 表单**（解决你现在提出的“不能实时控制设置”问题）。
2. **IPv6 支持**（现代网络环境的基本需求，越早做改动越小）。
3. **多架构 CI Release**（让项目从“可编译”走向“可分发”）。

---

## 贡献与讨论

如果你对其中的某个方向特别感兴趣，建议按阶段拆分 Issue / PR：

- 每个阶段独立一个 milestone。
- 每个功能点尽量保持“单 PR 可 review、可测试、可回滚”。
- 涉及 eBPF 数据面改动的，必须同时更新集成测试 `tests/netns_test.sh`。

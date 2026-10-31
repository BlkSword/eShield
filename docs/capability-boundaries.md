# eShield 能力边界与不承诺项

> 版本：v0.5.0（2026-10-31）
>
> 本文面向运维、安全与售前：说明 eShield **能防什么、不能防什么、为什么、怎么缓解、是否会支持**。
> 部署前请先读完「1. 定位」与「3. 边界清单」；容量与规格见 [capacity-planning.md](capacity-planning.md)。

## 1. 定位

eShield 是**主机级 L3-L4 清洗盾**：eBPF/XDP 程序挂载在单台 Linux 主机的网卡 XDP 钩子上，
在数据包进入内核网络协议栈之前完成解析、匹配与丢弃，用于保护**这台主机自己的**网络服务。

它适用于：单机 / 边缘节点 / 源站 / 游戏服 / 内部服务的第一道防线。
它**不**适用于：替代云清洗、CDN、WAF、运营商级 DDoS 清洗；也**不**适用于跨主机流量调度。

一句话边界：**能更快地丢包、能按 IP/端口/协议限速、能扛住已识别的 L3-L4 Flood；
不能拦应用层攻击、不能扩容链路、不能保证零误封。**

## 2. 防护范围

**会处理（数据面生效）：**

| 能力 | 说明 |
|---|---|
| 黑名单 / 白名单 | 单个 IP 与 CIDR（LPM Trie），支持永久/限时封禁；白名单优先放行。 |
| Per-IP 速率限制 | 指数衰减窗口，超阈值封禁或丢弃（`[rate_limit].block_mode`）。 |
| 按协议 + 目的端口聚合限速 | 不依赖源地址，防伪造源 IP 绕过；**v0.5.0 起默认开启**。 |
| UDP / ICMP Flood 防护 | 无连接流量的 per-IP 与 per-port 速率抑制。 |
| SYN Flood 检测 | 单源 SYN 速率检测；可选 SYN Cookie 挑战（实验特性，默认关闭）。 |
| 端口/协议 ACL | `tcp`/`udp`/`icmp`/`icmpv6`/`any` + 端口/端口范围。 |
| GeoIP / ASN 过滤 | 按国家/ASN 的 CIDR 名单放行或封禁。 |
| 威胁情报 | 外部 feed 定时入库到黑名单。 |
| 防护项目 | 按 目的 IPv4 + 端口 + 协议 组合 PASS/DROP/DEFEND。 |
| 自适应封禁 / Trust Score / Danger Signal | 重复触发加长封禁、IP 信誉调制、系统压力联动。 |
| IPv4 非首片分片策略 | `pass` / `rate_limit`（默认）/ `drop`，**v0.5.0 新增**。 |
| L7 首包指纹 | 仅 TCP 首包前 8 字节特征匹配（不是 WAF）。 |

**不会处理：** HTTP/CC Flood、慢速攻击、DNS/HTTP 应用层放大、TLS 握手耗尽、
链路带宽耗尽、IPv6 扩展头 / 分片重组、任意协议的深度包检测（完整清单见下一节）。

## 3. 边界清单

每条边界给出：**现象**（现场会看到什么）、**原因**（为什么）、**缓解**（可执行动作）、
**计划**（是否会在后续版本支持）。

### B1. 不防 CC / HTTP Flood / 慢速攻击

- **现象**：单 IP 以 500 rps 请求 HTTP 服务（v0.4.8 实测），`/api/stats` 各拦截计数均不增长，
  请求全部进入业务进程；应用被打挂时 eShield 看起来"什么都没做"。
- **原因**：数据面只有 IP/端口/协议与 TCP 首包 8 字节指纹，没有 TCP 流重组、HTTP 解析、
  会话状态，也没有针对"每连接每请求"的应用层速率模型。合法的 HTTP Flood 特征与正常请求一致。
- **缓解**：
  1. 前置 CDN / WAF / nginx `limit_req`/`limit_conn` 做应用层限流；
  2. 用 `[port_rate_limit]` 对 80/443 做目的端口总量兜底（会误伤该端口的突发业务，阈值需实测）；
  3. 用 `[conn_track]` 拦半连接耗尽类攻击；用 `[trust_score]` + 自适应降低可疑 IP 的额度。
- **计划**：**不计划**在 XDP 数据面实现通用 L7 防御（会显著抬高每包成本并逼近 verifier 指令上限）；
  应用层防护交给前置 WAF/CDN。

### B2. 不抗链路带宽耗尽

- **现象**：攻击流量超过网卡/链路 pps 或带宽后，即使 eShield 把包都丢了，内核仍要处理中断与
  `ksoftirqd`，`sshd` 卡顿、控制面 API 变慢，严重时整机失联；上行带宽被占满时下游无法收到任何包。
- **原因**：主机级软件只能在**收到包之后**丢弃；中断、DMA、驱动层开销已经发生，
  链路带宽更无法靠软件扩容。参考 [capacity-planning.md](capacity-planning.md) 的实测：
  135k pps 攻击下防御机系统繁忙 13%，正常流量 p95 延迟从 8.5ms 涨到 412ms。
- **缓解**：接入云厂商/运营商的流量清洗与 CDN；对入口做多级防护（上游清洗 + 本机 eShield）；
  攻击超过规格时优先保证管理面（SSH/API）可用。
- **计划**：**不计划**（物理与架构限制）。

### B3. 单 IP 粒度封禁会连带 NAT 用户；`soft` 模式缓解

- **现象**：`block_mode = "hard"`（默认）下，NAT 出口 / 共享代理 IP 上只要有一个用户触发限速，
  整个出口 IP 被写入黑名单，出口后所有用户的新连接超时/被重置（表现为"整段出口断网"）。
- **原因**：黑名单 key 是最小到单个 IP；数据面不知道 IP 后面有多少真实用户。
  `[rate_limit]`、UDP Flood、ICMP Flood 的 hard 模式都会写黑名单。
- **缓解**：v0.5.0 新增 `[rate_limit].block_mode = "soft"`：超限只丢弃超限包、**不写黑名单**，
  流量回落后自动恢复，把"整段出口不可用"降级为"超限包被丢"。
  其它配套：把 NAT 出口 IP 加入 `whitelist`；调大 `threshold`；开启 `dport_grouping` 或
  `[port_rate_limit]` 让不同业务端口不共享额度。
- **计划**：hard 仍为默认（对攻击源更有效）；soft 作为出口/NAT/共享代理场景的推荐配置，
  后续不排除按项目/端口维度指定 block_mode。

### B4. 伪造源 IP 会让 per-IP 计数失效（v0.5.0 用端口聚合兜底）

- **现象**（v0.4.8 实测）：以伪造随机源 IP 打 20k pps 时，per-IP 黑名单不触发、流量全部 PASS，
  `RATE_MAP` 被撑到 20000 条上限；分片流量大部分放行；单 IP 500rps 的 CC 不触发任何策略。
- **原因**：per-IP 限速/黑名单的 key 是源地址；源地址随机化后每个 IP 只出现一两次，
  永远到不了阈值，而且会挤占 LRU 表。
- **缓解**：v0.5.0 起 `[port_rate_limit]` **默认开启**：按「协议 + 目的端口」聚合限速，
  不依赖源地址；对非首片 IPv4 分片也按「协议 + 0 端口」聚合（`[xdp].fragment_policy` 默认 `rate_limit`）。
  可通过 `eshield_port_rate_blocked_total` 与 `port_rate_blocked` 观察命中。
- **计划**：已实现（v0.5.0）；更细的「目的 IP + 端口」维度需要更多 map 容量，暂未排期。

### B5. IPv4 非首片分片曾可绕过 L4 防护（v0.5.0 修复，可配置）

- **现象**（v0.4.8 实测）：非首片分片没有 L4 头，v0.4.x 会跳过端口 ACL/防护项目/TCP/UDP/ICMP/L7
  等全部模块，伪造源的分片 SYN/UDP Flood 整段放行。
- **原因**：非首片分片不含端口信息，按端口索引的模块无法匹配；v0.4.x 选择直接放行。
- **缓解**：v0.5.0 新增 `[xdp].fragment_policy`：
  - `rate_limit`（默认）：按「协议 + 0 端口」在 `PORT_RATE_MAP` 聚合限速，超阈值丢弃；
  - `drop`：直接丢弃所有非首片分片（最严格，可能影响合法大包路径的 PMTU/重组）；
  - `pass`：v0.4.x 兼容行为，不推荐。
  **注意**：`rate_limit` 依赖 `[port_rate_limit].enabled = true`；若把端口聚合限速关掉，
  分片实际等同 `pass`。
- **计划**：已实现（v0.5.0）。首片（offset=0，MF=1）仍带 L4 头，正常走完整模块。

### B6. generic XDP 与 native XDP 的性能差

- **现象**：`/api/stats` 的 `xdp_mode` 为 `generic`，吞吐/pps 明显低于 native；同机 CPU 更高。
- **原因**：native 在驱动收包路径执行；generic（SKB 模式）在分配 `sk_buff` 之后执行，
  每包都付出了 SKB 分配与协议栈准备的成本，且无法使用 XDP_TX 快速回包。
- **缓解**：设置 `[xdp].mode = "native"` 让挂载失败显式报错（避免"以为在 native"）；
  `disable_offloads = true` 会自动尝试关闭 `rx-gro-hw`/`tx-checksum` 后重试。
  virtio_net 在宿主机开启 GRO_HW/CSUM 时 guest 侧无解（`ethtool -k` 显示 `[fixed]`），
  只能用 generic 或改用直通网卡。
- **计划**：**不计划**（驱动能力限制）；容量规划请按 generic 的实测成本留余量。

### B7. SYN Cookie 代理是实验特性（默认关闭）

- **现象**：开启 `[syn_proxy].enabled = true` 后，部分真实客户端的连接在 30s 内失败；
  带 IP option 或带载荷的 SYN 被直接丢弃。
- **原因**：SYN Cookie 是无状态校验，挑战窗口内（`CHALLENGE_TIMEOUT_NS` = 30s）被挑战源的
  合法连接也会失败；仅 IPv4 TCP；有效 Cookie 熵 30 位（v0.4.8 起），不足以对抗有算力的定向爆破；
  带 IP option / 数据的 SYN 无法构造挑战包，只能丢弃。
- **缓解**：面向真实客户端的高流量服务**不要**开启该模块，改用 SYN Flood 检测 + 速率限制；
  只在"攻击几乎完全由 SYN 构成且客户端可重试"的场景短时开启。
- **计划**：保持实验特性；不承诺线上默认开启，不建议作为对外卖点。

### B8. L7 扫描只检查 TCP 首包 8 字节

- **现象**：跨 TCP 分段构造的攻击特征、编码变形、非首包特征均无法命中；HTTP 层面 attack 不被识别。
- **原因**：`[l7_scan]` 是"首包签名匹配"（最多 8 条，8 字节签名 + mask），不做 TCP 重组、
  不做 URL/Header 解析。
- **缓解**：把 L7 指纹当作"探测/扫描识别"的补充，不当作 WAF 使用；应用层防护交给前置 WAF。
- **计划**：**不计划**做流重组/完整 L7。

### B9. IPv6：无分片解析，无 SYN Cookie

- **现象**：IPv6 分片流量不会命中 `fragment_policy`（该策略仅 IPv4）；IPv6 的 TCP 不会进入
  Cookie 挑战；IPv6 分片包的协议字段是 44，端口类模块整体跳过。
- **原因**：解析器只处理固定 40 字节 IPv6 头，不遍历扩展头（分片头/路由头/AH 等 Σ）；
  SYN Cookie 打点只在 IPv4 路径实现。
- **缓解**：IPv6 依靠黑名单、GeoIP、per-IP 限速、SYN Flood 检测等**源地址级**能力；
  对 IPv6 分片攻击显式封禁源 IP/CIDR；必要时在边界设备丢弃 IPv6 分片。
- **计划**：IPv6 扩展头解析未排期；如确有需求，优先补「IPv6 分片头识别 + 复用分片策略」。

### B10. 小内存规格会拖垮整机（v0.5.0 启动预检）

- **现象**：400MB 内存实例装 nginx + eShield 后 `sshd` 失去响应（TCP 三次握手成功但 banner 不返回），
  整机近似失联。
- **原因**：eBPF map 预分配（约 75–82MB，见容量文档）+ 用户态进程 RSS（实测 ~48MB）+ 业务进程，
  在 ≤512MB 的机器上很容易触发 OOM；XDP 挂载后内核内存压力还会影响调度。
- **缓解**：v0.5.0 新增 `[limits]`：`refuse_memory_mb`（默认 256MB）以下拒绝启动，
  `min_memory_mb`（默认 512MB）以下打印告警；**不建议**用 `ESHIELD_ALLOW_LOW_MEMORY=1` 绕过，
  若必须绕过，请同时减少 map 规模/关闭模块并保证有 swap 或内存余量。
- **计划**：已实现（v0.5.0）；map 容量目前写死在 eBPF 侧，暂不支持按配置缩小。

### B11. Hub 不是高可用组件

- **现象**：Hub 单实例宕机期间，节点无法拉取/上报策略，`/api/hub/status` 显示未连接；
  Hub 的 redb 数据损坏或磁盘丢失会丢失聚合策略。
- **原因**：`eshield-hub` 是单进程 + 单机 redb 的有状态服务，没有多副本选主、没有共识复制；
  节点只做本地缓存与重试，不做一致性保证。
- **缓解**：Hub 放在有备份的机器上，定期备份 `/var/lib/eshield-hub`；
  节点侧保持本地策略自治（Hub 不可用时防护不中断）；多节点场景不要依赖 Hub 做实时决策。
- **计划**：非当前版本目标；如需高可用，建议在 Hub 前做冷备/手工切换。

### B12. "进程活着"不等于"防护生效"

- **现象**：`/healthz` 返回 200，但 `/ready` 返回 503，`xdp_attached=false`——此时流量是**裸奔**状态。
- **原因**：XDP 程序可能被驱动重置、被外部 `ip link set ... xdp off` 摘掉；
  v0.4.8 起后台每 15s 巡检挂载状态并在被摘掉时自动重挂，但重挂可能失败。
- **缓解**：监控与告警必须以 `/ready` 为准；把 `/ready` 503 与日志 `XDP 自动重挂失败` 一并告警；
  详情见 [operations.md](operations.md)。
- **计划**：持续增强（更多驱动兼容性验证）。

### B13. 运行环境硬性要求

- **现象**：非 root、无 BTF、内核 < 5.10、Windows 环境直接无法运行或加载失败。
- **原因**：eBPF CO-RE 需要 BTF；加载 XDP 需要 `CAP_BPF`/`CAP_NET_ADMIN` 等高权限；
  用户态依赖 Linux 专有 API（Aya）。
- **缓解**：按 [deployment.md](deployment.md) 检查 `ls /sys/kernel/btf/vmlinux` 与 capability；
  在 WSL2/Linux 构建测试，不要在 Windows 上尝试运行。
- **计划**：**不计划**支持 Windows / 无 BTF 内核。

### B14. 策略按单机生效，不做跨机流量调度

- **现象**：Hub 只负责同步"封谁/放谁"的策略，不会把攻击流量引走，也不会在节点间分摊负载。
- **原因**：eShield 是主机防护软件，不是清洗中心/负载均衡器。
- **缓解**：大流量场景在 DNS/Anycast/负载均衡层做流量调度，eShield 负责每台主机自己的兜底。
- **计划**：非目标。

## 4. 明确不承诺（面向验收与售前）

- 不承诺**零误封**；默认参数面向通用业务，NAT/共享出口/健康检查密集场景需按本文与
  [capacity-planning.md](capacity-planning.md) 调参。
- 不承诺**线速无开销**；所有流量都要付每包成本，数字见容量文档。
- 不承诺**应用层防护**（CC/HTTP Flood/慢速攻击/绕过）。
- 不承诺**链路扩容**或**上游清洗**能力。
- 不承诺 **Hub 高可用**、**跨机故障转移**。
- 不承诺在**低于最小规格**（512MB 内存）的环境稳定运行。
- 不承诺 **IPv6 分片/扩展头**、**SYN Cookie 对 IPv6 的支持**。
- 不承诺对**伪造源 IP 的 per-IP 识别**（已用端口聚合限速兜底，不是识别）。

## 5. 相关文档

- [capacity-planning.md](capacity-planning.md)：实测 CPU/内存数据、推荐规格、map 内存与调优。
- [operations.md](operations.md)：日常运维、升级回滚、审计链校验、map 水位告警、故障排查。
- [architecture.md](architecture.md)：数据包旅程与 BPF Map 布局。
- [deployment.md](deployment.md)：安装、systemd、容器、K8s 与 Hub 部署。
- [api.md](api.md)：REST API 与 Prometheus 指标。

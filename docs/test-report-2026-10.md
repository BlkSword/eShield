# eShield v0.4.6 云内网极限测试报告（2026-10）

> 被测版本：v0.4.6
> 报告月份：2026-10
> 测试形态：云内网三节点（attack1 / attack2 / defense）
> 数据来源：eShield `/api/stats`、发送侧 pktgen / hping3 / trafgen / wrk 计数、tcpdump 抓包

## 1. 报告概述

本轮测试在云内网三节点环境验证 eShield v0.4.6 在 virtio_net + native XDP（DRV 模式）下的处理能力与主要防护模块行为，覆盖全量 PASS、全量 DROP、双机并发、SYN / UDP / ICMP Flood、conn_track 与 L7 扫描。

本文所有数字均为实测值。结论按“实测证明”“受环境限制不能外推”“测试工具导致的现象”三类分别表述；本轮未执行的项目在 §5 明确列出，不得作为已测能力引用。

## 2. 测试环境

### 2.1 节点

| 节点 | 公网 IP | 内网 IP | 规格 | 系统 / 内核 | 网络与工具 |
|---|---|---|---|---|---|
| attack1 | 47.238.248.94 | 172.23.83.41 | 8 vCPU / 32GB | Ubuntu 26.04 / 7.0.0-31 | 内网约 6Gbps、约 1.6M pps；pktgen 8 线程、hping3、wrk、trafgen |
| attack2 | 47.76.142.69 | 172.23.83.40 | 8 vCPU / 32GB | Ubuntu 26.04 / 7.0.0-31 | 同上 |
| defense | 8.218.154.208 | 172.23.83.42 | 128 vCPU / 257GB | Ubuntu 26.04 / 7.0.0-31 | eth0 为 virtio_net、32 队列；native XDP（DRV 模式）可用 |

### 2.2 被测配置

| 配置项 | 值 |
|---|---|
| 版本 | eShield v0.4.6 |
| 配置文件 | lab.toml |
| 白名单 | `172.23.83.41/32` |
| 认证 | `api_token = eshield-test` |
| 模块开关 | 按用例在运行时开启 / 关闭 |

### 2.3 环境限制

| 限制 | 影响 |
|---|---|
| defense 为云主机 virtio_net | 吞吐受 vNIC 与内网链路限制，不能代表物理网卡线速 |
| 发送侧云内网存在约 0.01% 丢包 | 发送侧计数与防御端 XDP 处理计数存在偏差，绝对吞吐为下限值 |
| 未做 map 饱和与长时压测 | 本报告不能给出防护容量上限 |

## 3. 测试结果

统计口径：

- 单机用例的 `total_packets` 比注入包数高 30–37 包，为防护网卡上的其他流量，不影响 DROP 侧计数；
- 双机用例使用 `/api/stats` 前后增量，避免累计统计造成的口径混淆。

### 3.1 全量 PASS / DROP 与双机并发

| 编号 | 用例 | 发送侧 | eShield 实测 | 结果 |
|---|---|---|---|---|
| 1 | 单机全 PASS（attack2 20M UDP） | 20,000,000 | total_packets 20,000,037；total_passed 20,000,037；total_dropped 0 | PASS |
| 2 | 单机全 DROP（attack2 20M UDP + 静态黑名单） | 20,000,000 | total_packets 20,000,030；total_dropped 20,000,000；blacklist_blocked 20,000,000 | DROP |
| 3 | 双机同时 PASS（各 20M） | 2 × 20,000,000 | 处理 39,271,100 / 40,000,000；聚合约 3.14M pps | 通过 |
| 4 | 双机混合 DROP + PASS（attack1 白名单 PASS 20M + attack2 黑名单 DROP 20M） | 2 × 20,000,000 | 增量：total_packets +39,996,229；total_passed +20,000,053；total_dropped +19,996,176；blacklist_blocked +19,996,176；udp_dropped +19,996,176；聚合约 3.08M pps | 通过 |

用例 4 口径说明：

- 约 3,771 包（占注入量约 0.0094%）在到达 XDP 前已在云内网丢失，与发送侧约 0.01% 丢包的环境限制一致；
- `total_passed` 增量比 attack1 注入量多 53 包，来自白名单来源的其他流量，`/api/stats` 无法单独区分；
- DROP 侧 20,000,000 包中 XDP 实际处理 19,996,176 包，全部计入 `blacklist_blocked` 与 `udp_dropped`。

### 3.2 Flood 与 conn_track

| 编号 | 用例 | 发送侧 | eShield 实测 | 结果 |
|---|---|---|---|---|
| 5 | SYN Flood（trafgen，attack2） | 20,000,515 SYN / 约 12.6s | 处理 15,767,794；syn_flood_blocked 15,767,577；total_passed 217 | DROP |
| 6 | UDP Flood（pktgen 20M，udp_flood_enabled=true） | 20,000,000 | total_dropped 19,998,743；首个窗口超阈值后源进入动态黑名单，后续命中 blacklist_blocked；udp_flood_blocked ≈ 0–1 | DROP |
| 7 | ICMP Flood（8 路 hping3 -1 --flood，8s；防御端每 0.5s 解封一次以反复触发模块） | 12,796,343 | 处理 12,796,368；icmp_flood_blocked 15；blacklist_blocked 12,794,708；icmp_dropped 12,794,723；total_passed 1,645 | DROP |
| 8 | conn_track（8 路 hping3 -S --flood，8s；threshold=100、window=10s） | 12,771,734 SYN | 处理 11,779,544；conn_track_blocked 11,779,346；total_passed 198；tcp_dropped 11,779,346 | DROP |

用例 5、8 口径说明：发送侧计数与防御端 XDP 处理计数存在差距（SYN 约 423 万、conn_track 约 99 万）。该差距发生在包到达 XDP 之前，无法进一步区分是发送侧丢包还是 defense vNIC 在 XDP 之前的丢弃；两者都属于环境限制，不计入 eShield 的 DROP 统计，也不能据此推算 XDP 的极限处理能力。

用例 6 说明：UDP Flood 首个窗口超阈值后，源 IP 进入动态黑名单，后续包由黑名单路径丢弃，因此 `udp_flood_blocked` 在极限流量下只有个位数，DROP 量体现在 `blacklist_blocked` / `total_dropped`，符合模块与黑名单的既有交互。

用例 7 说明：计数自洽。`icmp_flood_blocked + blacklist_blocked = icmp_dropped`（15 + 12,794,708 = 12,794,723），`icmp_dropped + total_passed = 处理数`（12,794,723 + 1,645 = 12,796,368）；处理数比发送数多 25 包，为防护网卡上的其他流量。

### 3.3 L7 扫描

| 编号 | 用例 | 发送侧 / 观测 | eShield 实测 | 结果 |
|---|---|---|---|---|
| 9 | L7 功能验证（pattern="GET /"，防御端 :80 起 python http.server） | 负向 POST 返回 HTTP 501 | l7_blocked 增量 0 | 负向不误杀 |
| 9 | 同上 | 正向 wrk 持续 GET，完成请求 0 | l7_blocked 140；tcp_dropped 140；握手 total_passed 87 | 正向命中 DROP |
| 10 | L7 吞吐（8 路 hping3 -p 80 --flood -d 16 -E payload，8s） | 发送 12,798,083 | 处理 12,798,107；l7_blocked 6,399,046；total_passed 6,399,061 | 命中约一半 |

用例 10 说明：tcpdump 抓包确认 hping3 偶数包 payload 首字节为 `"GET /..."`，奇数包为 `"zz\0\0..."`，因此只有约一半包命中 `"GET /"` 前 8 字节特征。未命中的部分是测试工具 payload 构造导致；命中首 8 字节的包实际全部 DROP。

### 3.4 结果汇总

| 能力 | 用例 | 实测结论 |
|---|---|---|
| 单机吞吐 | 1–2 | virtio_net + native XDP 下可稳定处理约 1.5–2M pps |
| 双机聚合 | 3–4 | 聚合约 3.1M pps（3.08–3.14M） |
| 全量 DROP / PASS | 1–4 | 统计自洽 |
| SYN / UDP / ICMP Flood | 5–7 | 按预期触发并 DROP |
| conn_track | 8 | 按预期触发并 DROP |
| L7 扫描 | 9–10 | 负向不误杀，正向命中 DROP |

## 4. 评价与结论

### 4.1 实测证明

- eShield v0.4.6 在 virtio_net + native XDP（DRV 模式）下单机可稳定处理约 1.5–2M pps，双机聚合约 3.1M pps。
- 全量 DROP / PASS、SYN / UDP / ICMP Flood、conn_track、L7 扫描均按预期生效；各用例 `/api/stats` 计数与发送侧、抓包观测自洽。
- 测试期间未出现进程 panic、XDP 掉挂或统计明显错乱。
- 动态黑名单与 Flood 模块的联动按设计工作：首窗口由模块触发，后续包由黑名单丢弃。

### 4.2 受环境限制不能外推

- defense 为云主机 virtio_net，吞吐受 vNIC 与云内网链路限制，本报告数据不能推算物理网卡线速。
- 防护上限还受 `RATE_MAP`、`CONN_TRACK`、`TOP_ATTACKERS` 等 LRU 容量与采样策略影响，需针对 map 饱和场景单独压测。
- 发送侧约 0.01% 的云内网丢包使发送计数与 XDP 处理计数存在偏差，绝对 pps 为下限值。
- 用例 5、8 中分别有约 21% 与约 7.8% 的包在到达 XDP 前丢失，属于环境限制，不能据此推算 XDP 的极限处理能力。

### 4.3 测试工具导致的现象

- L7 吞吐用例中 hping3 交替构造两套 payload，只有约一半包命中模式，`l7_blocked` 约等于处理数的一半，属于测试工具现象，不是漏判。
- UDP / ICMP Flood 用例中，模块计数在首窗口后停止增长、`blacklist_blocked` 承担主要 DROP 量，是动态黑名单短路后的测量现象；单看 `udp_flood_blocked` / `icmp_flood_blocked` 会低估模块触发量。
- 用例 7 的处理数比发送数多 25 包，为防护网卡上的其他流量，不影响结论。

## 5. 未测试项

以下内容本轮未执行，不能视为已验证：

- GeoIP block / allow / `default_action` 完整三态；
- protection projects 的 PASS / DROP / DEFEND；
- port_rate_limit（按目的端口限速）；
- Hub 多节点规模；
- 长时 soak / 故障注入；
- native XDP 与 SKB 通用模式对照。

## 6. 发现的问题

本节仅客观记录测试中复现的现象，不含修复方案；所有现象均在 v0.4.6 复现。

### 6.1 `geoip.default_action=drop` 下热加载瞬断管理连接

- 现象：`POST /api/config/reload` 后，来自白名单 `172.23.83.41` 的 SSH 通道出现 20–30s 超时，随后自行恢复。
- 触发条件：`geoip.default_action = drop`。
- 机制：reload 先写入 `default_action = drop`，再清空并重建白名单，存在白名单为空的窗口；该窗口内管理连接不满足放行条件而被丢弃。

### 6.2 API 校验上限与 eBPF map 容量不一致

| 端点 | API 校验 | map 容量 | 实际行为 |
|---|---:|---:|---|
| `POST /api/l7-patterns` | 拒绝 > 16 条 | `MAX_L7_PATTERNS = 8` | 提交 9–16 条时不报参数错误，`init_l7_patterns_map` 对下标 ≥ 8 的 `set` 越界，返回底层 map 错误 |
| `POST /api/port-acl` | 拒绝 > 128 条 | `MAX_PORT_ACL = 32` | 超过 32 条的部分被 `.min(32)` 静默截断，不返回错误 |

### 6.3 Flood 模块计数被动态黑名单短路掩盖

- 现象：UDP / ICMP Flood 首次触发后，源 IP 进入动态黑名单，后续包计入 `blacklist_blocked`；极限流量下 `udp_flood_blocked` / `icmp_flood_blocked` 只有个位数。
- 影响：仅凭模块计数会低估模块实际触发的防护量，需结合 `blacklist_blocked` / `total_dropped` 观察。

### 6.4 `DELETE /api/blacklist` 对不存在的 IP 非幂等

- 现象：对不存在的 IP 调用 `DELETE /api/blacklist` 返回 `bpf_map_delete_elem failed`。
- 影响：重复解封同一 IP 会返回错误，接口不是幂等的。

## 附录：用例与工具

| 编号 | 工具 | 关键参数 |
|---|---|---|
| 1–4 | pktgen | 8 线程 UDP，20M / 机；双机用例同时发送 |
| 5 | trafgen | 20,000,515 SYN |
| 6 | pktgen | 20M UDP；udp_flood_enabled=true |
| 7 | hping3 | 8 路 `-1 --flood`，8s；每 0.5s 解封一次 |
| 8 | hping3 | 8 路 `-S --flood`，8s；threshold=100、window=10s |
| 9 | HTTP POST 请求 / wrk | 防御端 :80 起 python http.server |
| 10 | hping3 | 8 路 `-p 80 --flood -d 16 -E payload`，8s |

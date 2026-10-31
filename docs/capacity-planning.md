# eShield 容量规划与实测数据

> 版本：v0.5.0（2026-10-31）
>
> 本文给出 v0.5.0 的**实测 CPU/内存数据、推荐部署规格、容量估算公式、eBPF map 内存占用与调优建议**。
> 所有数字都标注了测试条件，请按自己的场景留余量，不要跨条件外推。
> 能力边界见 [capability-boundaries.md](capability-boundaries.md)；运维流程见 [operations.md](operations.md)。

## 1. 结论先行

- **已识别攻击（命中黑名单/端口聚合限速等快路径）很便宜**：generic XDP 下约 **75 ns/包**（DROP），
  全放行约 **92 ns/包**（PASS）。
- **2 vCPU 防御机实测**：135k pps、540 万包、99.9% 由黑名单丢弃时，`eshield` 进程 CPU **5%（峰值 7%）**，
  系统繁忙 13%，load1 0.28，RSS 48MB，控制面 API 0.5ms——**2 vCPU 建议只承载 ≤150k pps 的
  "已识别"攻击**。
- **未识别流量/混合流量成本更高**：每包要走完全部模块且可能要写黑名单/事件，建议 **≥4 vCPU + native XDP**。
- **内存**：eBPF map 约 **75–82MB**（LRU 表按容量预分配）+ 进程 RSS 约 **48MB**，
  最小规格 512MB，推荐 1GB 起（业务进程另算）；低于 256MB 直接拒绝启动（`[limits]`）。
- **攻击期正常流量**：p50 延迟不变（3.4ms），p95 从 8.5ms 涨到 412ms（约 48 倍），
  成功率 96.9%→75.6%（其中部分归因于测试用的 `python http.server` 自身瓶颈）。
- **安全前提**：上述性能建立在**流量已被识别**的前提下；v0.4.8 实测显示伪造源 IP 的
  20k pps 流量可以完全绕过 per-IP 黑名单/限速（v0.5.0 已用默认开启的端口聚合限速兜底）。

## 2. 测试条件（数字仅在同等条件下可比）

### 2.1 单包 CPU 成本测试

| 项 | 值 |
|---|---|
| 机器 | 4 vCPU |
| XDP 模式 | generic（SKB） |
| 网络环境 | netns + veth（本机回环，无物理网卡/中断开销） |
| 打流工具 | `hping3`，打到该测试环境的吞吐上限 |
| 观察方式 | `eshield` 进程 CPU%（单核百分比）、`ksoftirqd` CPU% |

> 这是**纯数据面包处理**的净成本，不含物理网卡中断、业务进程、控制面统计同步。
> 真实网卡场景请用第 3 节的两机数据规划。

### 2.2 真实两机测试

| 项 | 值 |
|---|---|
| 防御机 | 2 vCPU |
| 攻击流量 | 135k pps、共 540 万包 |
| 丢弃构成 | 99.9% 由黑名单命中丢弃 |
| 观察指标 | `eshield` 进程 CPU、系统繁忙、load1、RSS、控制面 API 延迟 |
| 业务场景 | 正常 HTTP 请求（`python http.server`）与攻击并发 |

## 3. 实测数据

### 3.1 单包 CPU 成本（4 vCPU / generic XDP / netns + veth / hping3）

| 场景 | 单包成本 | 备注 |
|---|---:|---|
| UDP 全放行（PASS） | **≈ 92 ns/包** | 空规则下最贵路径：解析 + 全部模块分支 + 统计 |
| UDP 限速 + 黑名单（DROP） | **≈ 75 ns/包** | 超限后走黑名单快路径，比 PASS 更便宜 |
| SYN Flood 检测（DROP） | **≈ 75 ns/包** | 命中检测后丢弃 |

同组测试的整机观察：

| 指标 | 实测值 |
|---|---:|
| 吞吐 | 22 万 ~ 28 万 pps |
| `eshield` 进程 CPU（4 vCPU 机器） | **2%**（按单核百分比计，与 92ns/包 自洽） |
| `ksoftirqd` CPU | 1.4% ~ 1.8% |

### 3.2 真实两机网络（2 vCPU 防御机）

| 指标 | 实测值 |
|---|---:|
| 攻击速率 | 135k pps |
| 攻击总量 | 540 万包 |
| 黑名单丢弃占比 | 99.9% |
| `eshield` 进程 CPU | **5%（峰值 7%）** |
| 系统繁忙（`vmstat` sy/us/si 合计） | 13% |
| load1 | 0.28 |
| 进程 RSS | **48MB** |
| 控制面 API 延迟 | 0.5ms |

### 3.3 攻击期间正常流量的影响

| 指标 | 无攻击 | 攻击期间 | 变化 |
|---|---:|---:|---:|
| 延迟 p50 | 3.4 ms | 3.4 ms | 不变 |
| 延迟 p95 | 8.5 ms | **412 ms** | **约 48 倍** |
| 请求成功率 | 96.9% | 75.6% | -21.3 个百分点 |

> 说明：p95 恶化主要来自攻击包对协议栈/`ksoftirqd` 的挤压，以及测试业务端
> `python http.server` 单线程自身的瓶颈；生产环境请用真实业务进程复测。
> **结论：eShield 保的是"网络层不被彻底打瘫"，不是"攻击期业务延迟不变"。**

### 3.4 v0.4.8 实测的绕过面（v0.5.0 的改进依据）

| 场景 | v0.4.8 实测现象 | v0.5.0 对策 |
|---|---|---|
| 伪造随机源 IP，20k pps | per-IP 黑名单不触发，**全部 PASS**；`RATE_MAP` 被撑到 20000 条上限 | `[port_rate_limit].enabled` 默认 **true**，按协议+端口聚合限速 |
| IPv4 非首片分片 | 跳过全部 L4 模块，**大部分放行** | `[xdp].fragment_policy` 默认 `rate_limit`（可 `drop`） |
| 单 IP 500 rps HTTP（CC） | **不触发任何策略**（L3-L4 层看不到应用层特征） | 不解决（能力边界 B1），用端口聚合限速/WAF 兜底 |
| 400MB 实例装 nginx + eShield | `sshd` 失去响应（TCP 通、banner 不返回） | `[limits]` 启动内存预检 |

## 4. 推荐规格

| 档位 | vCPU | 内存 | XDP 模式 | 适用流量（**已识别攻击**） | 说明 |
|---|---:|---:|---|---:|---|
| 最小可用 | 1 | 512MB | generic | ≤ 50k pps | 仅防护 + 轻量业务；未做大流量实测，按起步配置使用 |
| 推荐 | 2 | 1GB | generic 或 native | **≤ 150k pps** | 与 3.2 实测条件一致（135k pps / CPU 5%） |
| 高流量 | ≥ 4 | 2GB+ | **native** | ≥ 300k pps | 未识别/混合流量务必用 native；业务进程需要额外资源 |

补充：

- 上面的 pps 是**已识别、能走快路径丢弃**的攻击；未被识别的流量每包要走更多模块，
  成本显著更高（参见 3.1：PASS 92ns 高于 DROP 75ns）。
- 如果机器同时跑 nginx/MySQL 等业务，请把业务内存与 CPU 单独计算，不要与上表叠加后压线。
- `[limits].refuse_memory_mb`（默认 256）以下**拒绝启动**；`min_memory_mb`（默认 512）以下告警。
  不建议用 `ESHIELD_ALLOW_LOW_MEMORY=1` 绕过。

## 5. 容量估算公式

### 5.1 数据面理论下限

```text
所需核数 ≈ 峰值 pps × 单包成本(75~92 ns) / 0.7
```

- 单包成本取 3.1 的实测值：DROP 约 75ns、PASS 约 92ns（都按 generic XDP）；
- `/ 0.7` 是给数据面留 30% CPU 余量（不要打满单核，否则中断/控制面线程会被饿死）。

示例：峰值 200k pps、按 92ns（全放行）估算：

```text
200000 × 92ns / 0.7 ≈ 0.026 核
```

**注意**：这个结果只覆盖"XDP 每包处理"本身，不含以下开销，因此不能直接当作机器规格：

1. 物理网卡中断与 `ksoftirqd`（3.2 实测攻击期系统繁忙 13%）；
2. 控制面（每秒统计同步、RingBuf 事件消费、30s 的 map 采样与 Trust 分布同步）；
3. 业务进程本身；
4. 攻击期的事件/日志/告警写放大。

### 5.2 工程取值建议

结合 3.2 的实测，按"已识别攻击"给出保守取值：

| 峰值 pps | 建议 vCPU | 建议 XDP 模式 |
|---:|---:|---|
| ≤ 50k | 1 | generic |
| ≤ 150k | 2 | generic/native |
| ≤ 300k | 4 | native |
| ≥ 300k 或未识别流量 | 4+ | native + 上游清洗 |

**未识别流量的成本可能比表中高数倍**：每包都要完整走模块、大量新源会争抢 LRU 表并写事件。
如果攻击源 IP 高度随机（每秒数十万新源），优先确认 `port_rate_blocked` 是否在增长，
并考虑 `[xdp].fragment_policy = "drop"` 等更激进的策略。

## 6. eBPF map 内存占用

### 6.1 容量与估算

LRU Hash 与 LPM Trie 等 map 在**创建时即按容量预分配**，与实际条目数无关；
下面的 `单条` 已包含内核哈希表元素头、LRU 链表节点与对齐开销（经验值，±20%）。

| Map | 类型 | 容量 | 单条估算 | 满容量估算 |
|---|---|---:|---:|---:|
| `BLACKLIST` | LRU Hash | 100,000 | ~96 B | ~9.2 MB |
| `RATE_MAP` | LRU Hash | 100,000 | ~104 B | ~10.0 MB |
| `RATE_MAP_PORT`（`dport_grouping` 用） | LRU Hash | 100,000 | ~112 B | ~10.7 MB |
| `TRUST_MAP` | LRU Hash | 100,000 | ~96 B | ~9.2 MB |
| `CONN_TRACK` | LRU Hash | 100,000 | ~88 B | ~8.4 MB |
| `SYN_PROXY_CONN` | LRU Hash | 100,000 | ~80 B | ~7.6 MB |
| `PORT_RATE_MAP` | LRU Hash | 4,096 | ~76 B | ~0.3 MB |
| `PROJECT_POLICY` | LRU Hash | 8,192 | ~56 B | ~0.4 MB |
| `TOP_ATTACKERS` | LRU Hash | 256 | ~80 B | ~20 KB |
| `WHITELIST_V4/V6` | LPM Trie | 1,024 × 2 | — | < 0.1 MB |
| `GEOIP_BLOCKED/ALLOWED_V4/V6` | LPM Trie | 4,096 × 4 | — | < 1 MB |
| `EVENTS` | RingBuf | — | — | **4 MB** |
| `PACKET_SAMPLES` | RingBuf | — | — | **16 MB** |
| `GLOBAL_STATS` 等 Array/PerCPU | — | — | — | < 0.1 MB |

**合计约 75–82 MB**（内核侧，记在 map 内存/memlock，不计入进程 RSS）。
其中 `EVENTS`(4MB) + `PACKET_SAMPLES`(16MB) 是固定占用，即使 `[packet_log].enabled = false`
也已在 map 创建时分配。

### 6.2 用户态内存

| 项 | 实测/估算 |
|---|---:|
| `eshield` 进程 RSS（135k pps 攻击中） | **48 MB** |
| 静态二进制大小 | 约 8.7 MB（musl，含嵌入的 eBPF 与单文件控制台） |
| redb 规则库 | 随持久化规则数量增长，通常 < 10 MB |
| 审计日志 | 按 `[audit].max_size_mb` 轮转（默认 100MB，保留 3 份历史 `audit.log.1~.3`） |

> 因此"512MB 最小规格"里，eShield 自身约占 125–130MB（map + RSS），
> 剩余留给 OS 与业务；400MB 实例上装 nginx + eShield 的 OOM 事故见 3.4。

### 6.3 用 `map-usage` 观测实际占用

```bash
# 当前各 map 条目数与上限
curl -H "Authorization: Bearer <token>" http://<host>:8720/api/map-usage | jq

# Prometheus 水位（0.8 为告警阈值）
eshield_map_usage_ratio{name="BLACKLIST"} 0.23
```

达到容量的 80% 以上会开始出现 LRU 淘汰（黑名单/信誉条目被挤掉，防护效果下降），
持续 >80% 时应下调阈值让表更早收敛，或按 6.1 扩大容量（需改 eBPF 侧常量并重新构建）。

## 7. 调优建议

### 7.1 优先跑 native XDP

```toml
[xdp]
mode = "native"          # 失败直接报错，避免静默降级
disable_offloads = true  # 自动尝试关闭 rx-gro-hw/tx-checksum 后重试
```

- virtio_net 在宿主机开启 GRO_HW/CSUM 时无法 native（`ethtool -k` 显示 `[fixed]`），
  只能 generic，此时按 5.2 的保守档位规划。
- 确认方式：`/api/stats` 的 `xdp_mode` 或启动日志 `attached XDP in native mode`。

### 7.2 关闭不需要的模块（未启用模块在数据面是零成本跳过）

| 配置 | 关闭后的收益 |
|---|---|
| `udp_flood_enabled = false` / `icmp_flood_enabled = false` | 少两条协议分支与会话计数 |
| `[l7_scan].enabled = false`（且 patterns 为空） | 跳过首包指纹循环 |
| `[conn_track].enabled = false` | 跳过半连接 map 访问 |
| `[trust_score].enabled = false` | 不更新信誉 map（省写放大） |
| `[geoip].enabled = false` | 跳过 4 张 LPM Trie 查询 |
| `[danger_signal].enabled = false` | 省控制面采样开销 |
| `[port_acl]` 为空 | 数据面直接跳过 32 次线性扫描 |
| `[protection_projects]` 为空 | 跳过项目策略查找 |

> `[port_rate_limit]` 与 `[xdp].fragment_policy` 建议保持默认开启——它们是抵抗"伪造源 + 分片"
> 绕过的兜底，代价只是一次 hash 查询。

### 7.3 `threshold` 与 `tick` 的关系（全局限速）

`[rate_limit].threshold` 不是 pps，而是**每个 tick 的突发信用**。
指数衰减稳态下：

```text
持续速率上限 ≈ (threshold × (1 - decay_num/decay_den)) / tick
默认（threshold=2000、tick=100ms、decay=7/8）≈ 2500 pps / 单 IP
```

- 业务是 NAT 出口/健康检查密集时，调大 `threshold` 或改用 `soft` 模式；
- 不要用极小 `tick_ms`（如 10ms）配合大 `threshold`：计数更新更频繁，写放大明显；
- `[port_rate_limit].threshold` 是**固定窗口**（不做衰减）：默认 2000/100ms ≈ 单端口 20000 pps，
  按业务端口峰值流量设定，聚合多源流量时阈值应明显高于 per-IP 阈值。

### 7.4 用 `soft` 模式保护 NAT/共享出口

```toml
[rate_limit]
block_mode = "soft"   # 超限只丢包，不写黑名单；流量回落自动恢复
```

- 效果：误封代价从"整段出口不可用"降为"超限包被丢"；
- 代价：攻击源不会被拉黑，后续包仍要走限速路径（比黑名单快路径贵一点，约 92ns vs 75ns）；
- hard 模式仍是默认，单机/独立 IP 场景无需改动。

### 7.5 分片策略

```toml
[xdp]
fragment_policy = "rate_limit"  # 默认；依赖 [port_rate_limit].enabled = true
```

- 伪造源的分片 Flood 无法靠 per-IP 计数识别，必须靠「协议 + 0 端口」聚合限速兜底；
- 若业务本身依赖 IP 分片（如异常 MTU/隧道），不要设 `drop`，用默认 `rate_limit`；
- 若把 `[port_rate_limit].enabled` 关掉，`rate_limit` 策略实际等同 `pass`。

### 7.6 监控与告警（早于用户投诉发现问题）

| 指标 | 建议动作 |
|---|---|
| `/ready` 非 200 | **最高优先级**：XDP 未挂载，流量裸奔 |
| `eshield_map_usage_ratio > 0.8` | LRU 开始淘汰，下调阈值或扩容；见 operations.md 的告警规则 |
| `eshield_port_rate_blocked_total` 持续增长 | 有伪造源/端口 Flood，确认阈值是否误伤业务 |
| `eshield_fragment_blocked_total` 增长 | 存在分片攻击或业务 MTU 异常 |
| `port_rate_blocked` / `rate_limited` 突增 | 误封风险，检查是否需 soft 模式或调大阈值 |
| `ksoftirqd` CPU 持续高 | 已接近本机处理上限，考虑 native XDP/加核/上游清洗 |

### 7.7 上线前的容量验证

```bash
# 1. 基线：本机基准（PACKETS/INTERVAL 可调）
sudo bash scripts/benchmark.sh

# 2. 混合洪水 soak + 黑名单饱和（DURATION/SATURATE 可调）
sudo SKIP_BUILD=1 DURATION=60 SATURATE=10000 bash tests/stress_local.sh

# 3. 攻击期观察
watch -n1 'curl -s localhost:8720/api/stats | jq "{pps:.current_pps,dps:.current_dps,port_rate:.port_rate_blocked,frag:.fragment_blocked}"'
watch -n1 'ps -o pid,pcpu,rss,comm -C eshield'
```

## 8. 相关文档

- [capability-boundaries.md](capability-boundaries.md)：能力边界、不承诺项与缓解手段。
- [benchmark.md](benchmark.md)：基准测试方法与 veth 大包吞吐数据。
- [operations.md](operations.md)：升级回滚、审计链、map 水位告警与故障排查。
- [architecture.md](architecture.md)：数据包旅程与 Map 布局。

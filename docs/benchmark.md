# eShield 基准测试

## 环境要求

- Linux 内核 >= 5.10，启用 BTF
- root 权限
- `hping3`

## 运行

```bash
# 先构建 release 二进制
cargo build --package eshield --target x86_64-unknown-linux-musl --release

# 运行基准测试
sudo bash scripts/benchmark.sh
```

可通过环境变量调整：

```bash
PACKETS=500000 INTERVAL=u1 sudo -E bash scripts/benchmark.sh
```

- `PACKETS`：每个场景发送的包数（默认 200000）
- `INTERVAL`：hping3 发包间隔（默认 `u1`，约 1us）

## 测试场景

1. **Baseline**：netns 已建立，但无 eShield 运行，测量原生 veth 转发/丢弃开销。
2. **XDP PASS**：eShield 已挂载，但无任何规则触发 DROP，测量 XDP 程序自身开销。
3. **XDP DROP**：eShield 将源 IP 加入黑名单，测量 XDP 早期 DROP 路径。

## 指标

- **pps**：每秒处理包数
- **time**：发送全部包耗时

## 示例报告

```text
=== eShield XDP Benchmark ===
packets: 200000, interval: u1

--- Baseline (no eShield) ---
  packets: 200000, time: 0.823s, pps: 243013

--- XDP PASS (no drop rules) ---
  packets: 200000, time: 0.891s, pps: 224467

--- XDP DROP (blacklist source) ---
  packets: 200000, time: 0.812s, pps: 246305
```

> 注意：veth 为虚拟设备，pps 受限于单核 CPU 与用户态/内核切换，物理网卡环境通常更高。

## veth 大包吞吐基准（内核 7.0 / 8 vCPU）

使用 `iperf3 -c <server> -t 5 -P 4` 在 netns + veth 环境测量 TCP 吞吐；
该环境只用于衡量 XDP 程序的相对开销，不代表物理网卡线速。

| 场景 | 吞吐 | 说明 |
|---|---:|---|
| Baseline（无 XDP） | 274.44 Gbps | veth 本机内存拷贝上限 |
| 最小 XDP_PASS 程序（原生模式） | 12.83 Gbps | veth 原生 XDP 自身瓶颈 |
| eShield PASS（原生模式，空规则） | 11.85 Gbps | 相对最小程序约 -7.6% |
| 最小 XDP_PASS 程序（SKB 通用模式） | 124.62 Gbps | 通用模式在 veth 上更快 |
| eShield PASS（SKB 通用模式，空规则） | 112.30 Gbps | 相对最小程序约 -9.9% |
| eShield PASS（原生 + 全部模块启用但不触发 DROP） | 11.81 Gbps | 相对空规则约 -0.3% |

结论：

- 本基准中 **veth 原生 XDP 本身是主要瓶颈**，eShield 程序相对最小 XDP_PASS
  只增加约 7%–10% 开销；
- 大包 TCP 场景下，开启速率限制 / Trust / 连接跟踪等模块后额外开销很小；
- 小包 / 高 pps 场景需要真实物理网卡 + `xdp-bench`/`pktgen` 复测，不能直接
  用本表推算线速。

## 高频写路径深度优化（v0.4.7）

针对持续攻击期的 map 写放大，数据面加入采样与热路径裁剪：

- `TRUST_MAP` PASS 更新：1/64 采样，按 64 倍权重补偿；
- `TRUST_MAP` DROP 更新：信任分已归零的源 1/16 采样写入；
- `BLACKLIST` 命中 `hit_count`：1/16 采样写入，单次补 16；
- `TOP_ATTACKERS` 热榜：1/16 采样写入，单次补 16；
- 黑名单命中的 DROP 不再写 RingBuf 事件（计数已由全局统计与 hit_count 覆盖）。

优化后 netns 全部 12 项集成测试、57 项单元测试、eBPF/userspace clippy 均通过，
内核 7.0 verifier 仍可正常加载。

## 云内网极限测试（v0.4.6，2026-10）

本节汇总 v0.4.6 在云内网三节点环境的实测结果：attack1 / attack2 各 8 vCPU / 32GB，
defense 128 vCPU / 257GB、eth0 为 virtio_net 32 队列、native XDP（DRV 模式）。
完整方法、口径与限制见 [test-report-2026-10.md](test-report-2026-10.md)。

| 场景 | 实测结果 |
|---|---|
| 单机全 PASS（20M UDP） | total_packets 20,000,037，全部 PASS，无 DROP |
| 单机全 DROP（20M UDP + 静态黑名单） | total_dropped 20,000,000，blacklist_blocked 20,000,000 |
| 双机同时 PASS（各 20M） | 处理 39,271,100 / 40,000,000，聚合约 3.14M pps |
| 双机混合 DROP + PASS（各 20M） | 聚合约 3.08M pps；DROP 侧 19,996,176 全部命中 blacklist_blocked |
| SYN Flood（trafgen 20M SYN） | syn_flood_blocked 15,767,577，total_passed 217 |
| UDP Flood（pktgen 20M） | total_dropped 19,998,743，首窗口后由动态黑名单承担 DROP |
| ICMP Flood（8 路 hping3，8s） | icmp_dropped 12,794,723，total_passed 1,645 |
| conn_track（8 路 hping3 SYN，8s） | conn_track_blocked 11,779,346，total_passed 198 |
| L7 扫描（pattern="GET /"） | 负向 POST 不误杀；正向 GET 全部命中 DROP |
| L7 吞吐（hping3 交替 payload，8s） | l7_blocked 6,399,046，约处理数一半；未命中由测试工具 payload 导致 |

结论：

- v0.4.6 在 virtio_net + native XDP（DRV 模式）下，单机可稳定处理约 1.5–2M pps，
  双机聚合约 3.1M pps；全量 DROP/PASS、SYN/UDP/ICMP Flood、conn_track 与 L7
  扫描均按预期生效。
- defense 为云主机 virtio_net，吞吐受 vNIC 与内网链路限制，不能据此推算物理网卡
  线速；发送侧约 0.01% 的云内网丢包使绝对 pps 为下限值。
- 测试中复现的 4 个问题（热加载瞬断、L7/端口 ACL 的 API 上限与 map 容量不一致、
  Flood 模块计数被黑名单短路掩盖、DELETE 黑名单非幂等）记录在完整报告，建议在
  v0.4.7 前评估。

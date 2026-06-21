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

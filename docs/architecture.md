# eShield 架构设计

## 三层架构

```text
┌─────────────────────────────────────────────────────────┐
│ 管理面 (Management Plane)                               │
│ Web Dashboard (axum+htmx) │ TUI (ratatui) │ CLI         │
└──────────────────────────────┬──────────────────────────┘
                               │ REST API / Config Watch
┌──────────────────────────────▼──────────────────────────┐
│ 控制面 (Control Plane) — Rust 用户态                     │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │
│ │ 配置管理 │ │ 事件消费 │ │ 指标聚合 │ │ 自适应   │    │
│ │ (热加载) │ │(Ring Buf)│ │(Per-CPU) │ │ 阈值引擎 │    │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘    │
└──────────────────────────────┬──────────────────────────┘
                               │ BPF Maps / Ring Buffer
┌──────────────────────────────▼──────────────────────────┐
│ 数据面 (Data Plane) — eBPF/XDP 内核态                    │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐    │
│ │ 包解析   │→│ 白名单   │→│ 速率限制 │→│ SYN Proxy│    │
│ │(有界读取)│ │ 匹配     │ │(滑窗计数)│ │(Cookie)  │    │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘    │
│            ↓                                             │
│ ┌──────────┐                                             │
│ │ L7 轻量  │ → 决策: PASS / DROP / TX / REDIRECT        │
│ │ 指纹扫描 │                                             │
│ └──────────┘                                             │
└─────────────────────────────────────────────────────────┘
```

## 数据包旅程

1. 包解析：有界读取 Eth / IP / TCP / UDP 头部（~20 ns）
2. 白名单：LPM Trie 查询 CIDR（~15 ns）
3. 黑名单：LRU Hash 查询（~15 ns）
4. 速率限制：Per-CPU LRU Hash + 指数衰减滑动窗口（~30 ns）
5. SYN Proxy：SYN Cookie 挑战（可选，~50 ns）
6. L7 扫描：读取前 64 字节载荷模式匹配（可选，~40 ns）
7. 默认放行：XDP_PASS（~5 ns）

单包总耗时约 175 ns，即 5.7 Mpps/核。

## BPF Maps

| Map | Type | Key | Value | 容量 | 用途 |
|---|---|---|---|---|---|
| WHITELIST | LPM Trie | CIDR (8B) | u8 | 1,024 | 白名单 |
| BLACKLIST | LRU Hash | u32 src_ip | BlockEntry | 100,000 | 动态封禁 |
| RATE_LIMIT | Per-CPU LRU Hash | u32 src_ip | RateCounter | 100,000 | 速率计数 |
| GLOBAL_STATS | Per-CPU Array | u32 | GlobalStats | 1 | 全局统计 |
| RULE_HITS | Per-CPU Array | u32 | u64 | 256 | 规则命中 |
| EVENTS | Ring Buffer | — | DropEvent | 4 MB | 事件上报 |
| COOKIE_SECRETS | Array | u32 | CookieSecret | 1 | SYN Cookie 密钥 |
| L7_PATTERNS | Array | u32 | L7Pattern | 16 | L7 特征 |
| CONFIG | Array | u32 | ConfigBlob | 1 | 运行时配置 |

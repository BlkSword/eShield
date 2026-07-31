# eShield 架构设计

## 三层架构

```text
┌──────────────────────────────────────────────────────────────┐
│ 管理面 (Management Plane)                                    │
│ Web Dashboard (axum+htmx) │ TUI (ratatui) │ CLI             │
└─────────────────────────────────┬────────────────────────────┘
                                  │ REST API / Config Watch
┌─────────────────────────────────▼────────────────────────────┐
│ 控制面 (Control Plane) — Rust 用户态                          │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │ 配置管理 │ │ 事件消费 │ │ 指标聚合 │ │ 自适应   │         │
│ │ (热加载) │ │(Ring Buf)│ │(Per-CPU) │ │ 阈值引擎 │         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │ 审计日志 │ │ 规则持久 │ │ API 认证 │ │ 威胁情报 │         │
│ │          │ │ (redb)   │ │ (Token)  │ │ 同步     │         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
└─────────────────────────────────┬────────────────────────────┘
                                  │ BPF Maps / Ring Buffer
┌─────────────────────────────────▼────────────────────────────┐
│ 数据面 (Data Plane) — eBPF/XDP 内核态                         │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │ 包解析   │→│ 白名单   │→│ 端口/协议│→│ 防护项目 │         │
│ │ IPv4/v6  │ │ 匹配     │ │ ACL      │ │ PASS/DROP│         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│            ↓                                                 │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │ GeoIP    │ │ SYN Proxy│ │ SYN Flood│ │ UDP/ICMP │         │
│ │ CIDR 匹配│ │(Cookie+  │ │ 检测     │ │ Flood    │         │
│ │          │ │  MSS)    │ │          │ │ 检测     │         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│            ↓                                                 │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │ L7 轻量  │ │ 速率限制 │ │ 黑名单   │ → 决策     │        │
│ │ 指纹扫描 │ │(滑窗计数)│ │ 检查     │  PASS/DROP│         │
│ └──────────┘ └──────────┘ └──────────┘ /TX        │         │
└──────────────────────────────────────────────────────────────┘
```

## 数据包旅程

1. 包解析：有界读取 Eth / IP(v4/v6) / TCP / UDP / ICMP 头部
2. 白名单：LPM Trie 查询 CIDR（IPv4 / IPv6）
3. 端口/协议 ACL：按目的端口与协议匹配 allow/drop 规则
4. 防护项目：按 目的 IPv4 + 端口 + 协议 查 `PROJECT_POLICY`（PASS 放行 / DROP 丢弃 / DEFEND 继续全局防御）
5. GeoIP/ASN：LPM Trie CIDR 匹配，支持自定义 CSV 或 MaxMind MMDB
6. TCP：SYN Proxy（IPv4 SYN-ACK Cookie 挑战 + ACK 校验）→ SYN Flood 速率检测
7. UDP Flood / ICMP Flood：按协议检测
8. L7 扫描：读取 TCP 首包载荷前 8 字节模式匹配
9. 速率限制：Per-CPU LRU Hash + 指数衰减滑动窗口
10. 黑名单：LRU Hash 查询到期自动解封
11. 默认放行：XDP_PASS

## BPF Maps

| Map | Type | Key | Value | 容量 | 用途 |
|---|---|---|---|---|---|
| WHITELIST_V4 | LPM Trie | WhitelistKeyV4 | u8 | 1,024 | IPv4 白名单 |
| WHITELIST_V6 | LPM Trie | WhitelistKeyV6 | u8 | 1,024 | IPv6 白名单 |
| BLACKLIST | LRU Hash | IpKey | BlockEntry | 100,000 | 动态封禁 |
| RATE_MAP | Per-CPU LRU Hash | IpKey | RateCounter | 100,000 | 速率计数 |
| GLOBAL_STATS | Per-CPU Array | u32 | GlobalStats | 1 | 全局统计 |
| EVENTS | Ring Buffer | — | DropEvent | 4 MB | 事件上报 |
| PACKET_SAMPLES | Ring Buffer | — | PacketSample | 16 MB | 采样包日志 |
| TOP_ATTACKERS | LRU Hash | IpKey | u64 | 256 | 高频攻击源热榜 |
| COOKIE_SECRETS | Array | u32 | CookieSecret | 1 | SYN Cookie 密钥 |
| L7_PATTERNS | Array | u32 | L7Pattern | 16 | L7 特征 |
| PORT_ACL | Array | u32 | PortAclEntry | 128 | 端口/协议 ACL |
| PROJECT_POLICY | LRU Hash | ProjectPolicyKey | ProjectPolicy | 8,192 | 防护项目策略（精确 IP 展开） |
| GEOIP_BLOCKED_V4 | LPM Trie | GeoIpKeyV4 | u8 | 4,096 | GeoIP IPv4 拦截 CIDR |
| GEOIP_BLOCKED_V6 | LPM Trie | GeoIpKeyV6 | u8 | 4,096 | GeoIP IPv6 拦截 CIDR |
| CONFIG | Array | u32 | RuntimeConfig | 1 | 运行时配置 |

## 控制面数据流

1. Web / CLI / SIGHUP 调用 `ControlState` 方法。
2. `ControlState` 通过 `tokio::sync::Mutex<Ebpf>` 串行访问 eBPF Maps。
3. 变更同时写入 redb（规则持久化 KV 存储），重启后自动恢复；持久化库会跳过 `BLACKLIST` reason，避免配置文件变更被历史动态黑名单覆盖。
4. Ring Buffer 事件由 `event_consumer` 批量聚合，更新 `Stats` 与自适应引擎。
5. 自适应引擎对重复触发规则的源 IP 追加动态黑名单。
6. 威胁情报后台任务按配置周期拉取公开/自定义 Feed，解析后动态阻断新命中 IP。

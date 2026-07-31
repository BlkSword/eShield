use aya_ebpf::{
    macros::map,
    maps::{Array, LpmTrie, LruHashMap, PerCpuArray, RingBuf},
};
use eshield_common::{
    BlockEntry, CookieSecret, GeoIpKeyV4, GeoIpKeyV6, GlobalStats, IpKey, L7Pattern, PortAclEntry,
    ProjectPolicy, ProjectPolicyKey, RateCounter, RateLimitConfig, RuntimeConfig, TrustEntry,
    WhitelistKeyV4, WhitelistKeyV6,
};

/// IPv4 白名单 CIDR 匹配（LPM Trie）
#[map]
pub static WHITELIST_V4: LpmTrie<WhitelistKeyV4, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv6 白名单 CIDR 匹配（LPM Trie）
#[map]
pub static WHITELIST_V6: LpmTrie<WhitelistKeyV6, u8> = LpmTrie::with_max_entries(1024, 0);

/// GeoIP/ASN IPv4 封禁 CIDR 匹配（LPM Trie）
#[map]
pub static GEOIP_BLOCKED_V4: LpmTrie<GeoIpKeyV4, u8> = LpmTrie::with_max_entries(4096, 0);

/// GeoIP/ASN IPv6 封禁 CIDR 匹配（LPM Trie）
#[map]
pub static GEOIP_BLOCKED_V6: LpmTrie<GeoIpKeyV6, u8> = LpmTrie::with_max_entries(4096, 0);

/// 动态黑名单（LRU Hash）：支持 IPv4 / IPv6
#[map]
pub static BLACKLIST: LruHashMap<IpKey, BlockEntry> = LruHashMap::with_max_entries(100000, 0);

/// 全局统计（Per-CPU，避免多核并发更新时的计数丢失）
#[map]
pub static GLOBAL_STATS: PerCpuArray<GlobalStats> = PerCpuArray::with_max_entries(1, 0);

/// 高频攻击源热榜（LRU Hash）：eBPF 数据面在命中黑名单时直接维护，
/// 用户态无需每秒全量扫描 BLACKLIST Map，降低控制面开销。
/// 容量大于展示 Top-N（20）以留出 LRU 抖动余量。
#[map]
pub static TOP_ATTACKERS: LruHashMap<IpKey, u64> = LruHashMap::with_max_entries(256, 0);

/// 事件 Ring Buffer
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// 采样包日志 Ring Buffer（默认关闭，开启后按采样率写入）
#[map]
pub static PACKET_SAMPLES: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// 运行时配置快照
#[map]
pub static CONFIG: Array<RuntimeConfig> = Array::with_max_entries(1, 0);

/// 速率限制参数
#[map]
pub static RATE_LIMIT_CFG: Array<RateLimitConfig> = Array::with_max_entries(1, 0);

/// Per-CPU Per-IP 速率计数器（LRU Hash）：支持 IPv4 / IPv6
#[map]
pub static RATE_MAP: LruHashMap<IpKey, RateCounter> = LruHashMap::with_max_entries(100000, 0);

/// SYN Cookie 密钥
#[map]
pub static COOKIE_SECRETS: Array<CookieSecret> = Array::with_max_entries(1, 0);

/// L7 轻量指纹模式
#[map]
pub static L7_PATTERNS: Array<L7Pattern> = Array::with_max_entries(16, 0);

/// 端口/协议 ACL 规则表
#[map]
pub static PORT_ACL: Array<PortAclEntry> = Array::with_max_entries(128, 0);

/// 防护项目策略表（LRU Hash）：按 目的 IPv4 + 目的端口 + 协议 精确匹配。
/// 控制面将项目的 target_ips CIDR 展开为精确 IP 后写入；容量 8192 条。
#[map]
pub static PROJECT_POLICY: LruHashMap<ProjectPolicyKey, ProjectPolicy> =
    LruHashMap::with_max_entries(8192, 0);

/// SYN Cookie 挑战模式表（LRU Hash）：源 IP → 进入挑战模式的单调时钟时间戳。
/// 触发 SYN Flood 阈值后该源的 SYN 被 Cookie 挑战；ACK 验证通过后删除条目恢复直通。
#[map]
pub static SYN_PROXY_CONN: LruHashMap<IpKey, u64> = LruHashMap::with_max_entries(100000, 0);

/// IP 信誉 Map（LRU Hash）：双向更新——PASS 加分，DROP 减分（v0.4.0）
#[map]
pub static TRUST_MAP: LruHashMap<IpKey, TrustEntry> = LruHashMap::with_max_entries(100000, 0);

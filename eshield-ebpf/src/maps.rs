use aya_ebpf::{
    macros::map,
    maps::{Array, LpmTrie, LruHashMap, PerCpuArray, RingBuf},
};
use eshield_common::{
    BlockEntry, CookieSecret, GlobalStats, IpKey, L7Pattern, PortAclEntry, RateCounter,
    RateLimitConfig, RuntimeConfig, WafRule, WhitelistKeyV4, WhitelistKeyV6,
};

/// IPv4 白名单 CIDR 匹配（LPM Trie）
#[map]
pub static WHITELIST_V4: LpmTrie<WhitelistKeyV4, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv6 白名单 CIDR 匹配（LPM Trie）
#[map]
pub static WHITELIST_V6: LpmTrie<WhitelistKeyV6, u8> = LpmTrie::with_max_entries(1024, 0);

/// 动态黑名单（LRU Hash）：支持 IPv4 / IPv6
#[map]
pub static BLACKLIST: LruHashMap<IpKey, BlockEntry> = LruHashMap::with_max_entries(100000, 0);

/// Per-CPU 全局统计
#[map]
pub static GLOBAL_STATS: PerCpuArray<GlobalStats> = PerCpuArray::with_max_entries(1, 0);

/// 规则命中计数
#[map]
pub static RULE_HITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

/// 事件 Ring Buffer
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

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

/// WAF 规则表
#[map]
pub static WAF_RULES: Array<WafRule> = Array::with_max_entries(8, 0);

/// Challenge 临时放行名单（LRU Hash）：value 为过期时间戳（ns）
#[map]
pub static CHALLENGE_ALLOWLIST: LruHashMap<IpKey, u64> = LruHashMap::with_max_entries(100000, 0);

/// SYN Proxy 连接表（LRU Hash）：已通过 Cookie 验证的连接元组
/// value 为过期时间戳（ns）
#[map]
pub static SYN_PROXY_CONN: LruHashMap<IpKey, u64> = LruHashMap::with_max_entries(100000, 0);

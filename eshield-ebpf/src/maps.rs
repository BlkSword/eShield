use aya_ebpf::{
    macros::map,
    maps::{Array, LpmTrie, LruHashMap, PerCpuArray, RingBuf},
};
use eshield_common::{
    BlockEntry, CookieSecret, GlobalStats, L7Pattern, RateCounter, RateLimitConfig, RuntimeConfig,
    WhitelistKey,
};

/// 白名单 CIDR 匹配（LPM Trie）
#[map]
pub static WHITELIST: LpmTrie<WhitelistKey, u8> = LpmTrie::with_max_entries(1024, 0);

/// 动态黑名单（LRU Hash）
#[map]
pub static BLACKLIST: LruHashMap<u32, BlockEntry> = LruHashMap::with_max_entries(100000, 0);

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

/// Per-CPU Per-IP 速率计数器（LRU Hash）
#[map]
pub static RATE_MAP: LruHashMap<u32, RateCounter> = LruHashMap::with_max_entries(100000, 0);

/// SYN Cookie 密钥
#[map]
pub static COOKIE_SECRETS: Array<CookieSecret> = Array::with_max_entries(1, 0);

/// L7 轻量指纹模式
#[map]
pub static L7_PATTERNS: Array<L7Pattern> = Array::with_max_entries(16, 0);

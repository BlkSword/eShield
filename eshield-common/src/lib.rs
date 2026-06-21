#![cfg_attr(not(feature = "userspace"), no_std)]

/// 共享的 Drop 事件结构，内核态通过 Ring Buffer 上报。
/// 必须 `#[repr(C)]` 且两边字段对齐一致。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DropEvent {
    pub timestamp_ns: u64,
    pub src_ip: u32,
    pub protocol: u8,
    pub rule_id: u16,
    pub padding: [u8; 5],
}

/// 命中规则 ID 枚举
pub mod rules {
    pub const UNKNOWN: u16 = 0;
    pub const BLACKLIST: u16 = 1;
    pub const RATE_LIMIT: u16 = 2;
    pub const SYN_FLOOD: u16 = 3;
    pub const L7_PATTERN: u16 = 4;
    pub const ADAPTIVE: u16 = 5;
}

/// 黑名单条目
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlockEntry {
    pub blocked_until_ns: u64,
    pub block_reason: u8,
    pub hit_count: u32,
    pub first_seen_ns: u64,
}

/// Per-IP 指数衰减速率计数器
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug)]
pub struct RateCounter {
    pub counter: u64,
    pub last_decay_ns: u64,
    pub padding: [u8; 16],
}

/// 白名单 LPM Trie Key（仅 IP 地址，前缀长度在 `aya_ebpf::maps::lpm_trie::Key` 中指定）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WhitelistKey {
    pub addr: u32,
}

/// 缓存行对齐的全局统计结构
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct GlobalStats {
    pub total_packets: u64,
    pub total_dropped: u64,
    pub total_passed: u64,
    pub syn_flood_blocked: u64,
    pub rate_limited: u64,
    pub l7_blocked: u64,
    pub _pad: [u8; 16],
}

const _: [(); 64] = [(); core::mem::size_of::<GlobalStats>()];

/// 配置运行时快照（内嵌到 CONFIG Map）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuntimeConfig {
    pub rate_limit_enabled: u8,
    pub syn_proxy_enabled: u8,
    pub l7_scan_enabled: u8,
    pub padding: [u8; 5],
}

/// 速率限制参数（内嵌到 RATE_LIMIT_CFG Map）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub threshold: u64,
    pub tick_ms: u64,
    pub decay_num: u64,
    pub decay_den: u64,
    pub block_duration_s: u64,
}

/// SYN Cookie 密钥（当前 + 上一个 bucket）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CookieSecret {
    pub current: [u8; 16],
    pub previous: [u8; 16],
    pub bucket_index: u64,
}

/// L7 轻量指纹模式（8 字节签名，验证器友好）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct L7Pattern {
    pub signature: u64,
    pub mask: u64,
    pub length: u8,
    pub action: u8,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            threshold: 200,
            tick_ms: 100,
            decay_num: 7,
            decay_den: 8,
            block_duration_s: 300,
        }
    }
}

#[cfg(feature = "userspace")]
mod userspace_impls {
    use super::{
        BlockEntry, CookieSecret, DropEvent, GlobalStats, L7Pattern, RateCounter,
        RateLimitConfig, RuntimeConfig, WhitelistKey,
    };
    use aya::Pod;

    unsafe impl Pod for DropEvent {}
    unsafe impl Pod for BlockEntry {}
    unsafe impl Pod for CookieSecret {}
    unsafe impl Pod for RateCounter {}
    unsafe impl Pod for L7Pattern {}
    unsafe impl Pod for WhitelistKey {}
    unsafe impl Pod for GlobalStats {}
    unsafe impl Pod for RuntimeConfig {}
    unsafe impl Pod for RateLimitConfig {}
}

#![cfg_attr(not(feature = "userspace"), no_std)]

pub mod pure;

/// IP 地址族
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpFamily {
    Ipv4 = 4,
    Ipv6 = 6,
}

impl IpFamily {
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            4 => Some(IpFamily::Ipv4),
            6 => Some(IpFamily::Ipv6),
            _ => None,
        }
    }
}

/// 通用 IP 键，用于 eBPF Map（黑名单、速率限制等）。
/// IPv4 映射为 IPv4-mapped IPv6 形式（前 12 字节为 0，后 4 字节为 IPv4 地址）。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct IpKey {
    pub family: u8,
    pub addr: [u8; 16],
    pub padding: [u8; 15],
}

impl IpKey {
    #[inline]
    pub fn from_ipv4(octets: [u8; 4]) -> Self {
        let mut addr = [0u8; 16];
        addr[12] = octets[0];
        addr[13] = octets[1];
        addr[14] = octets[2];
        addr[15] = octets[3];
        Self {
            family: IpFamily::Ipv4 as u8,
            addr,
            padding: [0; 15],
        }
    }

    #[inline]
    pub fn from_ipv6(addr: [u8; 16]) -> Self {
        Self {
            family: IpFamily::Ipv6 as u8,
            addr,
            padding: [0; 15],
        }
    }

    #[inline]
    pub fn family(&self) -> Option<IpFamily> {
        IpFamily::from_u8(self.family)
    }

    /// 取出 IPv4 地址（仅当 family == Ipv4 时有效）
    #[inline]
    pub fn ipv4(&self) -> u32 {
        u32::from_be_bytes([self.addr[12], self.addr[13], self.addr[14], self.addr[15]])
    }
}

/// 共享的 Drop 事件结构，内核态通过 Ring Buffer 上报。
/// 必须 `#[repr(C)]` 且两边字段对齐一致。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DropEvent {
    pub timestamp_ns: u64,
    pub src_ip: [u8; 16],
    pub family: u8,
    pub protocol: u8,
    pub rule_id: u16,
    pub dst_port: u16,
    pub padding: [u8; 2],
}

/// 命中规则 ID 枚举
pub mod rules {
    pub const UNKNOWN: u16 = 0;
    pub const BLACKLIST: u16 = 1;
    pub const RATE_LIMIT: u16 = 2;
    pub const SYN_FLOOD: u16 = 3;
    pub const L7_PATTERN: u16 = 4;
    pub const ADAPTIVE: u16 = 5;
    pub const API_BLOCK: u16 = 6;
    pub const PORT_ACL: u16 = 7;
    pub const UDP_FLOOD: u16 = 8;
    pub const ICMP_FLOOD: u16 = 9;
    pub const GEOIP: u16 = 10;
    pub const THREAT_INTEL: u16 = 11;
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

/// `blocked_until_ns == 0` 表示永久封禁。使用常量避免与 unix epoch 混淆。
pub const BLOCK_PERMANENT: u64 = 0;

// ---------------------------------------------------------------------------
// Trust Score (v0.4.0) — IP 双向信誉
// ---------------------------------------------------------------------------

/// IP 信誉条目。trust_score 范围 0..=1000，与许可/丢弃行为双向联动。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrustEntry {
    /// 0-1000，1000 = 完全可信，0 = 确认恶意
    pub trust_score: u32,
    /// 累计通过包数（供用户态统计展示）
    pub pass_count: u32,
    /// 累计丢弃包数
    pub drop_count: u32,
    /// 最后一次更新时间（ns，CLOCK_MONOTONIC）
    pub last_update_ns: u64,
    /// 信誉等级缓存：0=unknown, 1=trusted, 2=neutral, 3=suspicious, 4=malicious
    pub level: u8,
    pub padding: [u8; 3],
}

/// Trust Score 更新参数
pub const TRUST_MAX: u32 = 1000;
pub const TRUST_MIN: u32 = 0;
pub const TRUST_ADD_DIVISOR: u32 = 100;   // trust += (1000 - trust) / 100  慢慢加分
pub const TRUST_SUB_DIVISOR: u32 = 3;     // trust -= trust / 3             快速减分
pub const TRUST_DEFAULT: u32 = 500;       // 新 IP 默认中性

/// Per-IP 指数衰减速率计数器
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug)]
pub struct RateCounter {
    pub counter: u64,
    pub last_decay_ns: u64,
    pub padding: [u8; 16],
}

/// 白名单 LPM Trie Key（IPv4）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WhitelistKeyV4 {
    pub addr: u32,
}

/// 白名单 LPM Trie Key（IPv6）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WhitelistKeyV6 {
    pub addr: [u8; 16],
}

/// GeoIP/ASN 封禁 LPM Trie Key（IPv4）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GeoIpKeyV4 {
    pub addr: u32,
}

/// GeoIP/ASN 封禁 LPM Trie Key（IPv6）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GeoIpKeyV6 {
    pub addr: [u8; 16],
}

/// 缓存行对齐的全局统计结构
#[repr(C, align(128))]
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalStats {
    pub total_packets: u64,
    pub total_dropped: u64,
    pub total_passed: u64,
    pub syn_flood_blocked: u64,
    pub rate_limited: u64,
    pub l7_blocked: u64,
    pub udp_flood_blocked: u64,
    pub icmp_flood_blocked: u64,
    pub geoip_blocked: u64,
    pub blacklist_blocked: u64,
    pub tcp_rst_sent: u64,
    pub tcp_rst_fail: u64,
    pub tcp_rst_attempt: u64,
    /// 按协议维度统计的 DROP 数量（由 eBPF 数据面直接维护，避免依赖 RingBuf 事件）。
    pub tcp_dropped: u64,
    pub udp_dropped: u64,
    pub icmp_dropped: u64,
    pub other_dropped: u64,
}



/// 配置运行时快照（内嵌到 CONFIG Map）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuntimeConfig {
    pub rate_limit_enabled: u8,
    pub syn_proxy_enabled: u8,
    pub l7_scan_enabled: u8,
    pub ebpf_debug: u8,
    pub udp_flood_enabled: u8,
    pub icmp_flood_enabled: u8,
    pub geoip_enabled: u8,
    pub tcp_reset_on_drop: u8,
    /// 信任评分开关（v0.4.0）
    pub trust_enabled: u8,
    /// 全局危险等级：0=normal, 1=elevated, 2=critical
    pub danger_level: u8,
    pub padding: [u8; 6],
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
#[derive(Clone, Copy, Debug, Default)]
pub struct L7Pattern {
    pub signature: u64,
    pub mask: u64,
    pub length: u8,
    pub action: u8,
}

/// 端口/协议 ACL 规则条目（内嵌到 PORT_ACL Map）
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PortAclEntry {
    /// 0 = any, 1 = tcp, 17 = udp, 58 = icmpv6, 1 = icmp
    pub protocol: u8,
    /// 0 = any port
    pub dport_low: u16,
    pub dport_high: u16,
    /// 1 = allow, 2 = drop
    pub action: u8,
    pub padding: [u8; 11],
}

/// 防护项目策略键：按目的 IPv4 + 协议 + 端口匹配。
///
/// 当前 eBPF 栈空间有限，项目策略暂只支持 IPv4 精确地址匹配；
/// IPv6 流量回退到全局运行时策略。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProjectPolicyKey {
    pub addr: u32,
    pub dport: u16,
    pub protocol: u8,
    pub padding: u8,
}

/// 防护项目策略值。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProjectPolicy {
    /// 模块位图，见 `project_modules`
    pub flags: u16,
    /// 0=none, 1=pass, 2=drop, 3=defend
    pub action: u8,
    pub padding: [u8; 5],
}


/// 项目策略可用模块位图。
pub mod project_modules {
    pub const NONE: u16 = 0;
    pub const SYN_FLOOD: u16 = 1 << 0;
    pub const UDP_FLOOD: u16 = 1 << 1;
    pub const ICMP_FLOOD: u16 = 1 << 2;
    pub const RATE_LIMIT: u16 = 1 << 3;
    pub const ADAPTIVE: u16 = 1 << 4;
    pub const L7_SCAN: u16 = 1 << 5;
    pub const GEOIP: u16 = 1 << 6;
    pub const TCP_RESET: u16 = 1 << 7;
    pub const PORT_ACL: u16 = 1 << 8;
}

/// 项目策略动作。
pub mod project_action {
    pub const NONE: u8 = 0;
    pub const PASS: u8 = 1;
    pub const DROP: u8 = 2;
    pub const DEFEND: u8 = 3;
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
        BlockEntry, CookieSecret, DropEvent, GeoIpKeyV4, GeoIpKeyV6, GlobalStats, IpKey, L7Pattern,
        PortAclEntry, ProjectPolicy, ProjectPolicyKey, RateCounter, RateLimitConfig, RuntimeConfig,
        TrustEntry, WhitelistKeyV4, WhitelistKeyV6,
    };
    use aya::Pod;

    unsafe impl Pod for DropEvent {}
    unsafe impl Pod for BlockEntry {}
    unsafe impl Pod for CookieSecret {}
    unsafe impl Pod for RateCounter {}
    unsafe impl Pod for L7Pattern {}
    unsafe impl Pod for PortAclEntry {}
    unsafe impl Pod for ProjectPolicy {}
    unsafe impl Pod for ProjectPolicyKey {}
    unsafe impl Pod for WhitelistKeyV4 {}
    unsafe impl Pod for WhitelistKeyV6 {}
    unsafe impl Pod for GeoIpKeyV4 {}
    unsafe impl Pod for GeoIpKeyV6 {}
    unsafe impl Pod for IpKey {}
    unsafe impl Pod for GlobalStats {}
    unsafe impl Pod for RuntimeConfig {}
    unsafe impl Pod for RateLimitConfig {}
    unsafe impl Pod for TrustEntry {}
}

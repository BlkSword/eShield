#![cfg_attr(not(feature = "userspace"), no_std)]

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
    pub const WAF: u16 = 10;
    pub const GEOIP: u16 = 11;
    pub const CHALLENGE: u16 = 12;
    pub const THREAT_INTEL: u16 = 13;
}

/// WAF 规则在 eBPF Map 中的最大数量（保持较小以便 eBPF verifier 快速收敛）
pub const WAF_RULES_MAX: usize = 8;
/// WAF 单条匹配字段最大长度（签名长度，eBPF 快速路径只比较前 8 字节）
pub const WAF_FIELD_LEN: usize = 8;

/// WAF 动作
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WafAction {
    Drop = 1,
    Log = 2,
    Challenge = 3,
}

impl WafAction {
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(WafAction::Drop),
            2 => Some(WafAction::Log),
            3 => Some(WafAction::Challenge),
            _ => None,
        }
    }
}

/// WAF 规则条目（内嵌到 WAF_RULES Map）。
/// eBPF 快速路径使用 8 字节签名 + 掩码做按位比较，避免 verifier 状态爆炸。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WafRule {
    pub enabled: u8,
    pub priority: u8,
    pub action: u8,
    pub method: u8,
    pub match_flags: u8,
    pub padding: [u8; 3],
    pub path_sig: [u8; WAF_FIELD_LEN],
    pub path_mask: [u8; WAF_FIELD_LEN],
    pub host_sig: [u8; WAF_FIELD_LEN],
    pub host_mask: [u8; WAF_FIELD_LEN],
    pub user_agent_sig: [u8; WAF_FIELD_LEN],
    pub user_agent_mask: [u8; WAF_FIELD_LEN],
    pub body_sig: [u8; WAF_FIELD_LEN],
    pub body_mask: [u8; WAF_FIELD_LEN],
}

/// WAF 匹配标志位
pub mod waf_match {
    pub const METHOD: u8 = 1 << 0;
    pub const PATH_PREFIX: u8 = 1 << 1;
    pub const HOST: u8 = 1 << 2;
    pub const USER_AGENT: u8 = 1 << 3;
    pub const BODY_PREFIX: u8 = 1 << 4;
}

/// HTTP 方法枚举（eBPF 侧使用）
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Any = 0,
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Head = 5,
    Options = 6,
    Patch = 7,
}

impl HttpMethod {
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(HttpMethod::Any),
            1 => Some(HttpMethod::Get),
            2 => Some(HttpMethod::Post),
            3 => Some(HttpMethod::Put),
            4 => Some(HttpMethod::Delete),
            5 => Some(HttpMethod::Head),
            6 => Some(HttpMethod::Options),
            7 => Some(HttpMethod::Patch),
            _ => None,
        }
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.starts_with(b"GET") {
            HttpMethod::Get
        } else if bytes.starts_with(b"POST") {
            HttpMethod::Post
        } else if bytes.starts_with(b"PUT") {
            HttpMethod::Put
        } else if bytes.starts_with(b"DELETE") {
            HttpMethod::Delete
        } else if bytes.starts_with(b"HEAD") {
            HttpMethod::Head
        } else if bytes.starts_with(b"OPTIONS") {
            HttpMethod::Options
        } else if bytes.starts_with(b"PATCH") {
            HttpMethod::Patch
        } else {
            HttpMethod::Any
        }
    }
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
#[derive(Clone, Copy, Debug)]
pub struct GlobalStats {
    pub total_packets: u64,
    pub total_dropped: u64,
    pub total_passed: u64,
    pub syn_flood_blocked: u64,
    pub rate_limited: u64,
    pub l7_blocked: u64,
    pub udp_flood_blocked: u64,
    pub icmp_flood_blocked: u64,
    pub waf_blocked: u64,
    pub geoip_blocked: u64,
    pub challenge_issued: u64,
    pub _pad: [u8; 8],
}

const _: [(); 128] = [(); core::mem::size_of::<GlobalStats>()];

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
    pub waf_enabled: u8,
    pub challenge_enabled: u8,
    pub geoip_enabled: u8,
    pub tcp_reset_on_drop: u8,
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
        PortAclEntry, RateCounter, RateLimitConfig, RuntimeConfig, WafRule, WhitelistKeyV4,
        WhitelistKeyV6,
    };
    use aya::Pod;

    unsafe impl Pod for DropEvent {}
    unsafe impl Pod for BlockEntry {}
    unsafe impl Pod for CookieSecret {}
    unsafe impl Pod for RateCounter {}
    unsafe impl Pod for L7Pattern {}
    unsafe impl Pod for PortAclEntry {}
    unsafe impl Pod for WhitelistKeyV4 {}
    unsafe impl Pod for WhitelistKeyV6 {}
    unsafe impl Pod for GeoIpKeyV4 {}
    unsafe impl Pod for GeoIpKeyV6 {}
    unsafe impl Pod for IpKey {}
    unsafe impl Pod for GlobalStats {}
    unsafe impl Pod for RuntimeConfig {}
    unsafe impl Pod for RateLimitConfig {}
    unsafe impl Pod for WafRule {}
}

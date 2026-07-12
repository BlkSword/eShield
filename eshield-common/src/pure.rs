//! 与 eBPF helper / map 无关的纯计算函数集合。
//!
//! 这些函数不依赖任何 eBPF 运行时类型，因此可以在用户态通过 `cargo test`
//! 直接进行单元测试，覆盖 SYN Cookie、校验和、速率衰减、端口 ACL 等核心逻辑。

/// SYN Cookie 构造中的 32 位混合函数。
#[inline(always)]
pub fn mix(h: &mut u32, v: u32) {
    *h = h.wrapping_add(v);
    *h = h.rotate_left(5);
    *h = (*h) ^ ((*h) >> 16);
}

pub const COOKIE_SECRET_LEN: usize = 16;

/// 构造 SYN Cookie。
///
/// 高 8 位存储 MSS 档位索引，低 24 位存储 hash，以便 ACK 到达时回退 MSS。
#[inline(always)]
pub fn build_cookie(
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
    bucket: u32,
    mss_idx: u8,
    secret: &[u8; COOKIE_SECRET_LEN],
) -> u32 {
    let mut h: u32 = 0x9e37_79b9;
    mix(&mut h, u32::from_be(saddr));
    mix(&mut h, u32::from_be(daddr));
    mix(&mut h, ((sport as u32) << 16) | (dport as u32));
    mix(&mut h, bucket);
    mix(&mut h, mss_idx as u32);

    for &b in secret.iter() {
        mix(&mut h, b as u32);
    }

    ((mss_idx as u32) << 24) | (h & 0x00ff_ffff)
}

/// 根据客户端 MSS 选择档位索引。
#[inline(always)]
pub fn mss_to_idx(mss: u16) -> u8 {
    if mss >= 1460 {
        2
    } else if mss >= 1300 {
        1
    } else {
        0
    }
}

/// 标准 IP 校验和（RFC 1071）。
#[inline(always)]
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    for _ in 0..4 {
        if (sum >> 16) == 0 {
            break;
        }
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP 校验和 = 伪首部 + TCP 头/数据。
#[inline(always)]
pub fn tcp_checksum(saddr: u32, daddr: u32, proto: u8, tcp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += (saddr >> 16) & 0xffff;
    sum += saddr & 0xffff;
    sum += (daddr >> 16) & 0xffff;
    sum += daddr & 0xffff;
    sum += proto as u32;
    sum += tcp_data.len() as u32;

    let mut i = 0;
    while i + 1 < tcp_data.len() {
        let word = ((tcp_data[i] as u32) << 8) | (tcp_data[i + 1] as u32);
        sum += word;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }
    for _ in 0..4 {
        if (sum >> 16) == 0 {
            break;
        }
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 指数衰减速率计数器。
///
/// 根据 `elapsed_ns / tick_ns` 计算经历的刻度次数，并对 `counter`
/// 连续应用 `counter * decay_num / decay_den`，最后返回衰减后的值
///（调用者应自行 +1）。
#[inline(always)]
pub fn decay_counter(
    counter: u64,
    elapsed_ns: u64,
    tick_ns: u64,
    decay_num: u64,
    decay_den: u64,
) -> u64 {
    if tick_ns == 0 || decay_den == 0 {
        return counter;
    }
    let ticks = elapsed_ns / tick_ns;
    let effective_ticks = ticks.min(64);
    let mut decayed = counter;
    for _ in 0..effective_ticks {
        // 使用 wrapping_mul 避免编译器为 `(u64 * u64) / u64` 生成 128 位 __multi3 调用。
        decayed = decayed.wrapping_mul(decay_num).wrapping_div(decay_den);
    }
    decayed
}

/// 端口/协议 ACL 单条规则匹配结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMatch {
    /// 规则显式 allow，应停止继续匹配并放行。
    Allow,
    /// 规则显式 drop，应立即丢弃。
    Drop,
}

/// 判断单条 ACL 规则是否命中。
///
/// - `entry_protocol == 0` 表示任意协议。
/// - `dport_low == 0` 表示任意端口；`dport_high != 0` 表示端口范围。
/// - `action == 0` 表示空条目，返回 `None`。
/// - `action == 1` 返回 `Allow`；`action == 2` 返回 `Drop`。
#[inline(always)]
pub fn match_port_acl_entry(
    protocol: u8,
    dport: u16,
    entry_protocol: u8,
    dport_low: u16,
    dport_high: u16,
    action: u8,
) -> Option<AclMatch> {
    if action == 0 {
        return None;
    }

    if entry_protocol != 0 && entry_protocol != protocol {
        return None;
    }

    if dport_low != 0 {
        if dport_high != 0 {
            if dport < dport_low || dport > dport_high {
                return None;
            }
        } else if dport != dport_low {
            return None;
        }
    }

    match action {
        1 => Some(AclMatch::Allow),
        2 => Some(AclMatch::Drop),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mss_to_idx() {
        assert_eq!(mss_to_idx(0), 0);
        assert_eq!(mss_to_idx(535), 0);
        assert_eq!(mss_to_idx(536), 0);
        assert_eq!(mss_to_idx(1299), 0);
        assert_eq!(mss_to_idx(1300), 1);
        assert_eq!(mss_to_idx(1459), 1);
        assert_eq!(mss_to_idx(1460), 2);
        assert_eq!(mss_to_idx(9000), 2);
    }

    #[test]
    fn test_mix_deterministic() {
        let mut a = 0x9e37_79b9;
        mix(&mut a, 0x1234_5678);
        let mut b = 0x9e37_79b9;
        mix(&mut b, 0x1234_5678);
        assert_eq!(a, b);
        assert_ne!(a, 0x9e37_79b9);
    }

    #[test]
    fn test_build_cookie_encodes_mss_idx() {
        let secret = [0u8; COOKIE_SECRET_LEN];
        let c0 = build_cookie(0xc0a8_0001, 0xc0a8_0002, 12345, 80, 1, 0, &secret);
        let c2 = build_cookie(0xc0a8_0001, 0xc0a8_0002, 12345, 80, 1, 2, &secret);
        assert_eq!(c0 >> 24, 0);
        assert_eq!(c2 >> 24, 2);
        assert_ne!(c0 & 0x00ff_ffff, c2 & 0x00ff_ffff);
    }

    #[test]
    fn test_build_cookie_different_inputs_differ() {
        let secret = [0xabu8; COOKIE_SECRET_LEN];
        let c1 = build_cookie(0xc0a8_0001, 0xc0a8_0002, 12345, 80, 1, 1, &secret);
        let c2 = build_cookie(0xc0a8_0003, 0xc0a8_0002, 12345, 80, 1, 1, &secret);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_build_cookie_secret_changes_output() {
        let s1 = [0x00u8; COOKIE_SECRET_LEN];
        let s2 = [0xffu8; COOKIE_SECRET_LEN];
        let c1 = build_cookie(0xc0a8_0001, 0xc0a8_0002, 12345, 80, 1, 1, &s1);
        let c2 = build_cookie(0xc0a8_0001, 0xc0a8_0002, 12345, 80, 1, 1, &s2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_checksum_zero_for_zero_data() {
        assert_eq!(checksum(&[0, 0, 0, 0]), 0xffff);
    }

    #[test]
    fn test_checksum_known_ip_header() {
        // RFC 1071 示例：45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01 c0 a8 00 c7
        // 校验和字段 b8 61 置 0 后计算，应得到 0xb861（网络字节序）。
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&data), 0xb861);
    }

    #[test]
    fn test_checksum_odd_length() {
        // 奇数长度：最后一个字节高位补齐。
        let data = [0x00, 0x01, 0x02];
        let expected = {
            let mut sum: u32 = ((0x00u32) << 8) | 0x01;
            sum += (0x02u32) << 8;
            while (sum >> 16) != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !(sum as u16)
        };
        assert_eq!(checksum(&data), expected);
    }

    #[test]
    fn test_tcp_checksum_known_vector() {
        // 构造一个最小 TCP 段（全 0，20 字节），配合伪首部计算。
        let saddr = 0xc0a8_0001u32;
        let daddr = 0xc0a8_0002u32;
        let tcp = [0u8; 20];
        let cs = tcp_checksum(saddr, daddr, 6, &tcp);
        // 手工按同样算法计算验证一致性。
        let mut sum: u32 = 0;
        sum += (saddr >> 16) & 0xffff;
        sum += saddr & 0xffff;
        sum += (daddr >> 16) & 0xffff;
        sum += daddr & 0xffff;
        sum += 6u32;
        sum += tcp.len() as u32;
        for pair in tcp.chunks(2) {
            let word = if pair.len() == 2 {
                ((pair[0] as u32) << 8) | (pair[1] as u32)
            } else {
                (pair[0] as u32) << 8
            };
            sum += word;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let expected = !(sum as u16);
        assert_eq!(cs, expected);
    }

    #[test]
    fn test_decay_counter_zero_elapsed() {
        assert_eq!(decay_counter(100, 0, 100_000_000, 7, 8), 100);
    }

    #[test]
    fn test_decay_counter_one_tick() {
        // 100 * 7 / 8 = 87
        assert_eq!(decay_counter(100, 100_000_000, 100_000_000, 7, 8), 87);
    }

    #[test]
    fn test_decay_counter_multiple_ticks() {
        // 100 * (7/8)^3 = 100 * 343 / 512 = 66
        assert_eq!(decay_counter(100, 300_000_000, 100_000_000, 7, 8), 66);
    }

    #[test]
    fn test_decay_counter_caps_at_64_ticks() {
        let v1 = decay_counter(1_000_000, 64 * 100_000_000, 100_000_000, 7, 8);
        let v2 = decay_counter(1_000_000, 10_000 * 100_000_000, 100_000_000, 7, 8);
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_decay_counter_zero_denominator() {
        // 不应 panic，返回原值。
        assert_eq!(decay_counter(100, 100_000_000, 100_000_000, 7, 0), 100);
    }

    #[test]
    fn test_port_acl_match_any_any_drop() {
        assert_eq!(
            match_port_acl_entry(6, 80, 0, 0, 0, 2),
            Some(AclMatch::Drop)
        );
    }

    #[test]
    fn test_port_acl_match_protocol_specific() {
        assert_eq!(
            match_port_acl_entry(6, 80, 6, 80, 80, 2),
            Some(AclMatch::Drop)
        );
        assert_eq!(match_port_acl_entry(17, 80, 6, 80, 80, 2), None);
    }

    #[test]
    fn test_port_acl_match_port_range() {
        assert_eq!(
            match_port_acl_entry(6, 443, 6, 1, 1024, 2),
            Some(AclMatch::Drop)
        );
        assert_eq!(
            match_port_acl_entry(6, 443, 6, 1, 1024, 1),
            Some(AclMatch::Allow)
        );
        assert_eq!(match_port_acl_entry(6, 4433, 6, 1, 1024, 2), None);
    }

    #[test]
    fn test_port_acl_match_any_protocol_specific_port() {
        assert_eq!(
            match_port_acl_entry(17, 53, 0, 53, 53, 2),
            Some(AclMatch::Drop)
        );
    }

    #[test]
    fn test_port_acl_match_empty_action() {
        assert_eq!(match_port_acl_entry(6, 80, 6, 80, 80, 0), None);
    }
}

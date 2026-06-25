use aya_ebpf::{bindings::xdp_action, helpers::gen::bpf_ktime_get_ns, programs::XdpContext};
use core::mem;

use crate::maps::COOKIE_SECRETS;
use crate::parser::{ptr_at, ptr_at_mut, EthHdr, IpHdr, TcpHdr, ETH_HDR_LEN};
use crate::syn_flood;
use eshield_common::IpKey;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const BUCKET_DURATION_S: u64 = 60;
const VALID_BUCKETS: u8 = 2;
const COOKIE_SECRET_LEN: usize = 16;

/// 处理 SYN 包：发送 SYN-ACK Cookie 并丢弃原始 SYN。
/// 返回 Some(XDP_TX) 表示已处理，None 表示不是纯 SYN 包。
pub fn handle_syn(ctx: &XdpContext, ip: *const IpHdr, ip_hdr_len: usize) -> Option<u32> {
    let tcp: *const TcpHdr = unsafe { ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len)? };

    let flags = unsafe { (*tcp).flags() };
    if flags != TCP_FLAG_SYN {
        return None;
    }

    // 仅支持标准 20 字节 IP/TCP 头，避免 options 改写和校验和越界
    if ip_hdr_len != 20 {
        return None;
    }
    let tcp_hdr_len = (unsafe { (*tcp).doff() } as usize) * 4;
    if tcp_hdr_len != 20 {
        return None;
    }

    // 预先确保所有需要改写的头都可访问，避免后续大量栈计算后失去包边界信息
    unsafe {
        ptr_at_mut::<EthHdr>(ctx, 0)?;
        ptr_at_mut::<IpHdr>(ctx, ETH_HDR_LEN)?;
        ptr_at_mut::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len)?;
    }

    let saddr = unsafe { (*ip).saddr };
    let daddr = unsafe { (*ip).daddr };
    let sport = u16::from_be(unsafe { (*tcp).source });
    let dport = u16::from_be(unsafe { (*tcp).dest });
    let original_seq = u32::from_be(unsafe { (*tcp).seq });

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let src_key = IpKey::from_ipv4(saddr.to_ne_bytes());
    if syn_flood::handle_syn_flood(ctx, &src_key, TCP_FLAG_SYN, now_ns) {
        return Some(xdp_action::XDP_DROP);
    }

    let secret = COOKIE_SECRETS.get(0)?;

    let now_s = now_ns / 1_000_000_000;
    let bucket = now_s / BUCKET_DURATION_S;

    let secret_bytes = if bucket == secret.bucket_index {
        &secret.current
    } else if bucket == secret.bucket_index.saturating_sub(1) {
        &secret.previous
    } else {
        // 降级到 current，避免时间桶未轮换时全部丢弃
        &secret.current
    };

    let mss_idx = 0u8; // 简化：固定默认 MSS
    let cookie = build_cookie(
        saddr,
        daddr,
        sport,
        dport,
        bucket as u32,
        mss_idx,
        secret_bytes,
    );

    if send_synack(ctx, ip_hdr_len, cookie, original_seq).is_ok() {
        Some(xdp_action::XDP_TX)
    } else {
        Some(xdp_action::XDP_DROP)
    }
}

/// 处理 ACK 包：验证 Cookie，合法则放行给协议栈。
/// 返回 Some(action) 表示已处理，None 表示不是 ACK 包。
pub fn handle_ack(ctx: &XdpContext, ip: *const IpHdr, ip_hdr_len: usize) -> Option<u32> {
    let tcp: *const TcpHdr = unsafe { ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len)? };

    let flags = unsafe { (*tcp).flags() };
    // 仅处理 ACK 且不含 SYN 的包
    if flags & TCP_FLAG_ACK == 0 || flags & TCP_FLAG_SYN != 0 {
        return None;
    }

    let ack_seq = u32::from_be(unsafe { (*tcp).ack_seq });
    // ack_seq = cookie + 1，因此期望的 cookie 需要回退
    let expected = ack_seq.wrapping_sub(1);
    let mss_idx = (expected >> 24) as u8;

    let secret = COOKIE_SECRETS.get(0)?;

    let saddr = unsafe { (*ip).saddr };
    let daddr = unsafe { (*ip).daddr };
    let sport = u16::from_be(unsafe { (*tcp).source });
    let dport = u16::from_be(unsafe { (*tcp).dest });

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let now_s = now_ns / 1_000_000_000;
    let current_bucket = now_s / BUCKET_DURATION_S;

    for offset in 0..VALID_BUCKETS {
        let bucket = current_bucket.saturating_sub(offset as u64);
        let secret_bytes = if bucket == secret.bucket_index {
            &secret.current
        } else if bucket == secret.bucket_index.saturating_sub(1) {
            &secret.previous
        } else {
            continue;
        };

        let computed = build_cookie(
            saddr,
            daddr,
            sport,
            dport,
            bucket as u32,
            mss_idx,
            secret_bytes,
        );
        if computed == expected {
            return Some(xdp_action::XDP_PASS);
        }
    }

    // Cookie 无法匹配任何有效桶，交由后续逻辑处理（可能是正常 ACK）
    None
}

#[inline(always)]
fn build_cookie(
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

    // 高 8 位存 MSS 索引，低 24 位存 hash
    ((mss_idx as u32) << 24) | (h & 0x00ff_ffff)
}

#[inline(always)]
fn mix(h: &mut u32, v: u32) {
    *h = h.wrapping_add(v);
    *h = h.rotate_left(5);
    *h = (*h) ^ ((*h) >> 16);
}

/// 将原始 SYN 包改写为 SYN-ACK 并从同一网卡发出。
/// 调用者已通过 ptr_at_mut 保证 eth/ip/tcp 头可访问。
fn send_synack(
    ctx: &XdpContext,
    ip_hdr_len: usize,
    cookie: u32,
    original_seq: u32,
) -> Result<(), ()> {
    const TCP_HDR_LEN: usize = 20;

    // 改写以太网头：交换 MAC
    let eth: *mut EthHdr = unsafe { ptr_at_mut::<EthHdr>(ctx, 0).ok_or(())? };
    unsafe {
        mem::swap(&mut (*eth).src, &mut (*eth).dst);
    }

    // 改写 IP 头：交换地址、重置 TTL、重算校验和
    let ip_mut: *mut IpHdr = unsafe { ptr_at_mut::<IpHdr>(ctx, ETH_HDR_LEN).ok_or(())? };
    unsafe {
        mem::swap(&mut (*ip_mut).saddr, &mut (*ip_mut).daddr);
        (*ip_mut).ttl = 64;
        (*ip_mut).check = 0;
        let ip_bytes = core::slice::from_raw_parts(ip_mut as *const u8, ip_hdr_len);
        (*ip_mut).check = checksum(ip_bytes);
    }

    // 改写 TCP 头
    let tcp_offset = ETH_HDR_LEN + ip_hdr_len;
    let tcp_mut: *mut TcpHdr = unsafe { ptr_at_mut::<TcpHdr>(ctx, tcp_offset).ok_or(())? };
    unsafe {
        mem::swap(&mut (*tcp_mut).source, &mut (*tcp_mut).dest);

        (*tcp_mut).seq = cookie.to_be();
        (*tcp_mut).ack_seq = original_seq.wrapping_add(1).to_be();

        // flags: SYN+ACK
        let doff = (*tcp_mut).doff_flags & 0xf000;
        (*tcp_mut).doff_flags = doff | (u16::from_be_bytes([0x00, TCP_FLAG_SYN | TCP_FLAG_ACK]));
        (*tcp_mut).window = u16::to_be(65535);
        (*tcp_mut).check = 0;

        // TCP 校验和 = 伪首部 + TCP 头
        let tcp_bytes = core::slice::from_raw_parts(tcp_mut as *const u8, TCP_HDR_LEN);
        let saddr_host = u32::from_be((*ip_mut).saddr);
        let daddr_host = u32::from_be((*ip_mut).daddr);
        (*tcp_mut).check = tcp_checksum(saddr_host, daddr_host, 6, tcp_bytes);
    }

    Ok(())
}

#[inline(always)]
fn checksum(data: &[u8]) -> u16 {
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

#[inline(always)]
fn tcp_checksum(saddr: u32, daddr: u32, proto: u8, tcp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // 伪首部
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

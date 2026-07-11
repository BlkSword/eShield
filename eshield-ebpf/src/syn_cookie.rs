use aya_ebpf::{bindings::xdp_action, helpers::gen::bpf_ktime_get_ns, programs::XdpContext};
use core::mem;

use crate::maps::{COOKIE_SECRETS, GLOBAL_STATS};
use crate::parser::{ptr_at, ptr_at_mut, EthHdr, IpHdr, TcpHdr, ETH_HDR_LEN};
use eshield_common::pure::{build_cookie, checksum, mss_to_idx, tcp_checksum};
use crate::syn_flood;
use eshield_common::IpKey;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_OPT_MSS: u8 = 2;
const BUCKET_DURATION_S: u64 = 60;
const VALID_BUCKETS: u8 = 2;

/// MSS 档位表，高 8 位 cookie 用索引编码。
const MSS_TABLE: [(u8, u16); 3] = [(0, 536), (1, 1300), (2, 1460)];

/// 处理 SYN 包：发送 SYN-ACK Cookie 并丢弃原始 SYN。
/// 返回 Some(XDP_TX) 表示已处理，None 表示不是纯 SYN 包。
pub fn handle_syn(ctx: &XdpContext, ip: *const IpHdr, ip_hdr_len: usize) -> Option<u32> {
    let tcp: *const TcpHdr = unsafe { ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len)? };

    let flags = unsafe { (*tcp).flags() };
    if flags != TCP_FLAG_SYN {
        return None;
    }

    // 仅支持标准 20 字节 IP 头；TCP 头仅支持无 options(20) 或单个 MSS option(24)。
    if ip_hdr_len != 20 {
        return None;
    }
    let tcp_hdr_len = (unsafe { (*tcp).doff() } as usize) * 4;
    if tcp_hdr_len != 20 && tcp_hdr_len != 24 {
        return None;
    }

    // 预先确保所有需要改写的头都可访问，避免后续大量栈计算后失去包边界信息
    unsafe {
        ptr_at_mut::<EthHdr>(ctx, 0)?;
        ptr_at_mut::<IpHdr>(ctx, ETH_HDR_LEN)?;
        ptr_at_mut::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len)?;
        // 若 TCP 头含 MSS option，需让 verifier 知道 24 字节可访问
        if tcp_hdr_len == 24 {
            ptr_at_mut::<[u8; 24]>(ctx, ETH_HDR_LEN + ip_hdr_len)?;
        }
    }

    let saddr = unsafe { (*ip).saddr };
    let daddr = unsafe { (*ip).daddr };
    let sport = u16::from_be(unsafe { (*tcp).source });
    let dport = u16::from_be(unsafe { (*tcp).dest });
    let original_seq = u32::from_be(unsafe { (*tcp).seq });

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let src_key = IpKey::from_ipv4(saddr.to_ne_bytes());
    if syn_flood::handle_syn_flood(ctx, &src_key, TCP_FLAG_SYN, now_ns) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                (*stats).syn_flood_blocked += 1;
            }
        }
        return Some(xdp_action::XDP_DROP);
    }

    // 解析客户端 MSS，选择合适档位
    let client_mss = parse_mss(ctx, ETH_HDR_LEN + ip_hdr_len, tcp_hdr_len);
    let mss_idx = client_mss.map(mss_to_idx).unwrap_or(0);

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

    let cookie = build_cookie(
        saddr,
        daddr,
        sport,
        dport,
        bucket as u32,
        mss_idx,
        secret_bytes,
    );

    if send_synack(ctx, ip_hdr_len, tcp_hdr_len, mss_idx, cookie, original_seq).is_ok() {
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


/// 解析 TCP MSS 选项。当前仅处理 24 字节 TCP 头（含单个 MSS option）的情况。
#[inline(always)]
fn parse_mss(ctx: &XdpContext, tcp_offset: usize, tcp_hdr_len: usize) -> Option<u16> {
    if tcp_hdr_len != 24 {
        return None;
    }
    let opts_offset = tcp_offset + 20;
    let kind = unsafe { *ptr_at::<u8>(ctx, opts_offset)? };
    let len = unsafe { *ptr_at::<u8>(ctx, opts_offset + 1)? };
    if kind != TCP_OPT_MSS || len != 4 {
        return None;
    }
    let b0 = unsafe { *ptr_at::<u8>(ctx, opts_offset + 2)? };
    let b1 = unsafe { *ptr_at::<u8>(ctx, opts_offset + 3)? };
    Some(((b0 as u16) << 8) | (b1 as u16))
}

/// 将原始 SYN 包改写为 SYN-ACK 并从同一网卡发出。
/// 调用者已通过 ptr_at_mut 保证 eth/ip/tcp 头可访问。
fn send_synack(
    ctx: &XdpContext,
    ip_hdr_len: usize,
    original_tcp_hdr_len: usize,
    mss_idx: u8,
    cookie: u32,
    original_seq: u32,
) -> Result<(), ()> {
    // 复用原始 SYN 的 TCP options 空间回传 MSS；没有空间则保持 20 字节头。
    let new_tcp_hdr_len = original_tcp_hdr_len;

    // 改写 TCP 头前再次确认访问边界（含 option 空间）
    let tcp_offset = ETH_HDR_LEN + ip_hdr_len;
    if new_tcp_hdr_len == 24 {
        unsafe { ptr_at_mut::<[u8; 24]>(ctx, tcp_offset).ok_or(())? };
    }
    let tcp_mut: *mut TcpHdr = unsafe { ptr_at_mut::<TcpHdr>(ctx, tcp_offset).ok_or(())? };

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


    unsafe {
        mem::swap(&mut (*tcp_mut).source, &mut (*tcp_mut).dest);

        (*tcp_mut).seq = cookie.to_be();
        (*tcp_mut).ack_seq = original_seq.wrapping_add(1).to_be();

        // flags: SYN+ACK，doff 反映新的 TCP 头长度
        let doff = (new_tcp_hdr_len as u16 / 4) << 12;
        let flags = u16::from_be_bytes([0x00, TCP_FLAG_SYN | TCP_FLAG_ACK]);
        (*tcp_mut).doff_flags = doff | flags;
        (*tcp_mut).window = u16::to_be(65535);
        (*tcp_mut).check = 0;

        // 回写 MSS 选项到 options 区域（仅 24 字节头时 option 空间为 4 字节）
        if new_tcp_hdr_len == 24 {
            let opt_base = (tcp_mut as *mut u8).add(20);
            *opt_base.add(0) = TCP_OPT_MSS;
            *opt_base.add(1) = 4;
            let mss_val = MSS_TABLE[mss_idx as usize].1;
            *opt_base.add(2) = (mss_val >> 8) as u8;
            *opt_base.add(3) = (mss_val & 0xff) as u8;
        }

        // TCP 校验和 = 伪首部 + TCP 头
        let tcp_bytes = core::slice::from_raw_parts(tcp_mut as *const u8, new_tcp_hdr_len);
        let saddr_host = u32::from_be((*ip_mut).saddr);
        let daddr_host = u32::from_be((*ip_mut).daddr);
        (*tcp_mut).check = tcp_checksum(saddr_host, daddr_host, 6, tcp_bytes);
    }

    Ok(())
}


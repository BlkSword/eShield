use aya_ebpf::{bindings::xdp_action, helpers::gen::bpf_ktime_get_ns, programs::XdpContext};
use core::mem;

use crate::maps::{COOKIE_SECRETS, SYN_PROXY_CONN};
use crate::parser::{ptr_at, ptr_at_mut, EthHdr, IpHdr, TcpHdr, ETH_HDR_LEN};
use crate::syn_flood;
use eshield_common::pure::{build_cookie, checksum, mss_to_idx, tcp_checksum};
use eshield_common::IpKey;

pub const NO_ACTION: u32 = u32::MAX;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_OPT_MSS: u8 = 2;
const BUCKET_DURATION_S: u64 = 60;
const VALID_BUCKETS: u8 = 2;
/// 挑战模式标记的过期时间：超过后自动恢复直通，避免合法客户端被永久挑战。
const CHALLENGE_TIMEOUT_NS: u64 = 120_000_000_000;

/// MSS 档位表，高 8 位 cookie 用索引编码。
const MSS_TABLE: [(u8, u16); 3] = [(0, 536), (1, 1300), (2, 1460)];

/// 处理 SYN 包（IPv4 TCP）。
///
/// 降级式挑战（Katran 式）：
/// - 源 IP 未触发速率阈值：直通内核协议栈（对正常流量零影响）。
/// - 源 IP 触发 SYN Flood 阈值：进入挑战模式，SYN 被改写为 SYN-ACK Cookie
///   挑战包（XDP_TX），伪造源无法通过验证，SYN Flood 在 XDP 层被清洗；
///   合法客户端响应 Cookie 后由 `handle_ack` 解除挑战，后续连接直通。
///
/// 返回 NO_ACTION 表示未处理（应直通或交给后续模块），否则返回应执行的 action。
pub fn handle_syn(ctx: &XdpContext, ip: *const IpHdr, ip_hdr_len: usize) -> u32 {
    let tcp: *const TcpHdr = match unsafe { ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len) } {
        Some(t) => t,
        None => return NO_ACTION,
    };

    let flags = unsafe { (*tcp).flags() };
    if flags != TCP_FLAG_SYN {
        return NO_ACTION;
    }

    let saddr = unsafe { (*ip).saddr };
    let src_key = IpKey::from_ipv4(saddr.to_ne_bytes());

    // 挑战模式检查：已在挑战列表且未过期 → 直接挑战
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let mut challenged = false;
    if let Some(ts) = SYN_PROXY_CONN.get(&src_key) {
        if now_ns.saturating_sub(ts) < CHALLENGE_TIMEOUT_NS {
            challenged = true;
        } else {
            let _ = SYN_PROXY_CONN.remove(&src_key);
        }
    }

    if !challenged {
        // 速率检测：超限则进入挑战模式并挑战（替代直接拉黑，给合法客户端证明机会）。
        // 统计由主流程统一处理（XDP_TX → syn_flood_blocked；XDP_DROP → total_dropped），
        // 此处不重复累加。
        if syn_flood::handle_syn_flood(ctx, &src_key, TCP_FLAG_SYN, now_ns) {
            let _ = SYN_PROXY_CONN.insert(&src_key, &now_ns, 0);
            challenged = true;
        } else {
            // 未超限：直通内核，正常三次握手
            return NO_ACTION;
        }
    }

    // 以下为挑战路径：解析 MSS、构造 Cookie、回 SYN-ACK
    // 仅支持标准 20 字节 IP 头；TCP 头仅支持无 options(20) 或单个 MSS option(24)。
    if ip_hdr_len != 20 {
        return NO_ACTION;
    }
    let tcp_hdr_len = (unsafe { (*tcp).doff() } as usize) * 4;
    if tcp_hdr_len != 20 && tcp_hdr_len != 24 {
        return NO_ACTION;
    }

    // 预先确保所有需要改写的头都可访问，避免后续大量栈计算后失去包边界信息
    unsafe {
        if ptr_at_mut::<EthHdr>(ctx, 0).is_none() {
            return NO_ACTION;
        }
        if ptr_at_mut::<IpHdr>(ctx, ETH_HDR_LEN).is_none() {
            return NO_ACTION;
        }
        if ptr_at_mut::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len).is_none() {
            return NO_ACTION;
        }
        // 若 TCP 头含 MSS option，需让 verifier 知道 24 字节可访问
        if tcp_hdr_len == 24 && ptr_at_mut::<[u8; 24]>(ctx, ETH_HDR_LEN + ip_hdr_len).is_none() {
            return NO_ACTION;
        }
    }

    let daddr = unsafe { (*ip).daddr };
    let sport = u16::from_be(unsafe { (*tcp).source });
    let dport = u16::from_be(unsafe { (*tcp).dest });
    let original_seq = u32::from_be(unsafe { (*tcp).seq });

    // 解析客户端 MSS，选择合适档位
    let client_mss = parse_mss(ctx, ETH_HDR_LEN + ip_hdr_len, tcp_hdr_len);
    let mss_idx = client_mss.map(mss_to_idx).unwrap_or(0);

    let secret = match COOKIE_SECRETS.get(0) {
        Some(s) => s,
        None => return xdp_action::XDP_PASS,
    };

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
        xdp_action::XDP_TX
    } else {
        xdp_action::XDP_DROP
    }
}

/// 处理 ACK 包：验证 Cookie，合法则解除该源 IP 的挑战模式并放行。
/// 返回 NO_ACTION 表示不是本代理产生的 ACK 包，否则返回应执行的 XDP action。
pub fn handle_ack(ctx: &XdpContext, ip: *const IpHdr, ip_hdr_len: usize) -> u32 {
    let tcp: *const TcpHdr = match unsafe { ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len) } {
        Some(t) => t,
        None => return NO_ACTION,
    };

    let flags = unsafe { (*tcp).flags() };
    // 仅处理 ACK 且不含 SYN 的包
    if flags & TCP_FLAG_ACK == 0 || flags & TCP_FLAG_SYN != 0 {
        return NO_ACTION;
    }

    let saddr = unsafe { (*ip).saddr };
    let src_key = IpKey::from_ipv4(saddr.to_ne_bytes());

    // 快速路径：源 IP 不在挑战列表中则无需验证 Cookie。
    // 正常流量（绝大多数）只做一次 map 查询，避免每个 ACK 包都做 Cookie 计算。
    let now_ns = unsafe { bpf_ktime_get_ns() };
    match SYN_PROXY_CONN.get(&src_key) {
        Some(ts) if now_ns.saturating_sub(ts) < CHALLENGE_TIMEOUT_NS => {}
        Some(_) => {
            let _ = SYN_PROXY_CONN.remove(&src_key);
            return NO_ACTION;
        }
        None => return NO_ACTION,
    }

    let ack_seq = u32::from_be(unsafe { (*tcp).ack_seq });
    // ack_seq = cookie + 1，因此期望的 cookie 需要回退
    let expected = ack_seq.wrapping_sub(1);
    let mss_idx = (expected >> 24) as u8;

    let secret = match COOKIE_SECRETS.get(0) {
        Some(s) => s,
        None => return NO_ACTION,
    };

    let daddr = unsafe { (*ip).daddr };
    let sport = u16::from_be(unsafe { (*tcp).source });
    let dport = u16::from_be(unsafe { (*tcp).dest });

    let now_s = now_ns / 1_000_000_000;
    let current_bucket = now_s / BUCKET_DURATION_S;

    let mut i: u8 = 0;
    while i < VALID_BUCKETS {
        let bucket = current_bucket.saturating_sub(i as u64);
        let secret_bytes = if bucket == secret.bucket_index {
            &secret.current
        } else if bucket == secret.bucket_index.saturating_sub(1) {
            &secret.previous
        } else {
            i += 1;
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
            // Cookie 验证通过：解除挑战模式，后续该源的 SYN 直通内核正常握手。
            let _ = SYN_PROXY_CONN.remove(&src_key);
            return xdp_action::XDP_PASS;
        }
        i += 1;
    }

    // Cookie 无法匹配任何有效桶，交由后续逻辑处理（可能是正常 ACK）
    NO_ACTION
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

use aya_ebpf::{bindings::xdp_action, helpers::gen::bpf_csum_diff, programs::XdpContext};
use core::mem;

use crate::maps::{COOKIE_SECRETS, SYN_PROXY_CONN};
use crate::parser::{ptr_at, ptr_at_mut, EthHdr, IpHdr, TcpHdr, ETH_HDR_LEN};
use crate::rate_counter::{update_rate_counter, RateUpdate};
use eshield_common::pure::{build_cookie, mss_to_idx};
use eshield_common::IpKey;

/// 与主流程共享的包上下文（见 crate::main::PacketCtx）。
/// ctx 从 pc 内存读取（verifier 栈追踪保持 ctx 类型）；
/// 注意：ctx 不能作为本模块函数的入参——LLVM 参数提升会把 ctx 展开为
/// data/data_end 指针，callee prologue 对入参指针的 u32 零扩展（<<= 32）
/// 会被 verifier 拒绝（"pointer arithmetic with <<= operator prohibited"）。
pub(crate) struct PacketCtxRef<'a> {
    pub(crate) ctx: &'a XdpContext,
    pub(crate) ip_hdr_len: usize,
    pub(crate) now_ns: u64,
}

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
/// `ip`/`tcp` 指针由调用方完成边界检查。
#[inline(never)]
pub fn handle_syn(pc: &PacketCtxRef, ip: *const IpHdr, tcp: *const TcpHdr) -> u32 {
    let flags = unsafe { (*tcp).flags() };
    if flags != TCP_FLAG_SYN {
        return NO_ACTION;
    }

    let saddr = unsafe { (*ip).saddr };

    // 挑战判断（含速率触发）在独立栈帧中完成，src_key/map 局部不与挑战路径叠加
    if !is_challenged_or_trigger(saddr, pc.now_ns) {
        // 未超限：直通内核，正常三次握手
        return NO_ACTION;
    }

    // 以下为挑战路径：解析 MSS、构造 Cookie、回 SYN-ACK
    // 仅支持标准 20 字节 IP 头；TCP 头仅支持无 options(20) 或单个 MSS option(24)。
    if pc.ip_hdr_len != 20 {
        return NO_ACTION;
    }
    let tcp_hdr_len = (unsafe { (*tcp).doff() } as usize) * 4;
    if tcp_hdr_len != 20 && tcp_hdr_len != 24 {
        return NO_ACTION;
    }

    syn_challenge(pc, ip, tcp, tcp_hdr_len)
}

/// 挑战模式判断（独立栈帧）：源已在挑战列表 → true；未超限 → false（直通）；
/// 触发 SYN Flood 阈值 → 进入挑战模式并返回 true。
/// 统计由主流程统一处理（XDP_TX → syn_flood_blocked；XDP_DROP → total_dropped），此处不重复累加。
#[inline(never)]
fn is_challenged_or_trigger(saddr: u32, now_ns: u64) -> bool {
    let src_key = IpKey::from_ipv4(saddr.to_ne_bytes());

    if let Some(ts) = unsafe { SYN_PROXY_CONN.get(&src_key) } {
        if now_ns.saturating_sub(*ts) < CHALLENGE_TIMEOUT_NS {
            return true;
        }
        let _ = SYN_PROXY_CONN.remove(&src_key);
    }

    // 速率检测内联（不经过 syn_flood::handle_syn_flood 独立帧，
    // src_key 栈槽与本函数复用，节省 BPF 512 字节组合栈）。
    // 统计由主流程统一处理（XDP_TX → syn_flood_blocked；XDP_DROP → total_dropped）。
    let mut update = RateUpdate {
        counter: 0,
        threshold: 0,
        block_duration_s: 0,
    };
    if update_rate_counter(&src_key, now_ns, &mut update) && update.counter > update.threshold {
        let _ = SYN_PROXY_CONN.insert(&src_key, &now_ns, 0);
        return true;
    }
    false
}

/// SYN Cookie 挑战路径（独立栈帧，避免与 handle_syn 叠加撑爆 BPF 512 字节栈）。
/// 调用者保证：纯 SYN、IPv4 20 字节 IP 头、TCP 头 20/24 字节、源已在挑战列表。
#[inline(never)]
fn syn_challenge(
    pc: &PacketCtxRef,
    ip: *const IpHdr,
    tcp: *const TcpHdr,
    tcp_hdr_len: usize,
) -> u32 {
    let ctx = pc.ctx;

    // 预先确保所有需要改写的头都可访问，避免后续大量栈计算后失去包边界信息
    unsafe {
        if ptr_at_mut::<EthHdr>(ctx, 0).is_none() {
            return NO_ACTION;
        }
        if ptr_at_mut::<IpHdr>(ctx, ETH_HDR_LEN).is_none() {
            return NO_ACTION;
        }
        if ptr_at_mut::<TcpHdr>(ctx, ETH_HDR_LEN + pc.ip_hdr_len).is_none() {
            return NO_ACTION;
        }
        // 若 TCP 头含 MSS option，需让 verifier 知道 24 字节可访问
        if tcp_hdr_len == 24 && ptr_at_mut::<[u8; 24]>(ctx, ETH_HDR_LEN + pc.ip_hdr_len).is_none() {
            return NO_ACTION;
        }
    }

    let saddr = unsafe { (*ip).saddr };
    let daddr = unsafe { (*ip).daddr };
    let sport = u16::from_be(unsafe { (*tcp).source });
    let dport = u16::from_be(unsafe { (*tcp).dest });
    let original_seq = u32::from_be(unsafe { (*tcp).seq });

    // 解析客户端 MSS，选择合适档位
    let client_mss = parse_mss(ctx, ETH_HDR_LEN + pc.ip_hdr_len, tcp_hdr_len);
    let mss_idx = client_mss.map(mss_to_idx).unwrap_or(0);

    let secret = match COOKIE_SECRETS.get(0) {
        Some(s) => s,
        None => return xdp_action::XDP_PASS,
    };

    let now_s = pc.now_ns / 1_000_000_000;
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

    if send_synack(pc, tcp_hdr_len, mss_idx, cookie, original_seq).is_ok() {
        xdp_action::XDP_TX
    } else {
        xdp_action::XDP_DROP
    }
}

/// 处理 ACK 包：验证 Cookie，合法则解除该源 IP 的挑战模式并放行。
/// 返回 NO_ACTION 表示不是本代理产生的 ACK 包，否则返回应执行的 XDP action。
/// `tcp` 指针由调用方完成边界检查（见 handle_syn 注释）。
#[inline(never)]
pub fn handle_ack(pc: &PacketCtxRef, ip: *const IpHdr, tcp: *const TcpHdr) -> u32 {
    let flags = unsafe { (*tcp).flags() };
    // 仅处理 ACK 且不含 SYN 的包
    if flags & TCP_FLAG_ACK == 0 || flags & TCP_FLAG_SYN != 0 {
        return NO_ACTION;
    }

    let saddr = unsafe { (*ip).saddr };
    let src_key = IpKey::from_ipv4(saddr.to_ne_bytes());

    // 快速路径：源 IP 不在挑战列表中则无需验证 Cookie。
    // 正常流量（绝大多数）只做一次 map 查询，避免每个 ACK 包都做 Cookie 计算。
    let now_ns = pc.now_ns;
    match unsafe { SYN_PROXY_CONN.get(&src_key) } {
        Some(ts) if now_ns.saturating_sub(*ts) < CHALLENGE_TIMEOUT_NS => {}
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

    let mut i: u64 = 0;
    while i < VALID_BUCKETS as u64 {
        let bucket = current_bucket.saturating_sub(i);
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
/// 独立栈帧：内联会与 syn_challenge 帧叠加撑爆 BPF 512 字节组合栈。
#[inline(never)]
fn send_synack(
    pc: &PacketCtxRef,
    original_tcp_hdr_len: usize,
    mss_idx: u8,
    cookie: u32,
    original_seq: u32,
) -> Result<(), ()> {
    let ctx = pc.ctx;

    // 复用原始 SYN 的 TCP options 空间回传 MSS；没有空间则保持 20 字节头。
    let new_tcp_hdr_len = original_tcp_hdr_len;

    // 改写 TCP 头前再次确认访问边界（含 option 空间）
    if new_tcp_hdr_len == 24 {
        unsafe { ptr_at_mut::<[u8; 24]>(ctx, ETH_HDR_LEN + pc.ip_hdr_len).ok_or(())? };
    }
    let tcp_mut: *mut TcpHdr =
        unsafe { ptr_at_mut::<TcpHdr>(ctx, ETH_HDR_LEN + pc.ip_hdr_len).ok_or(())? };

    // 改写以太网头：交换 MAC
    let eth: *mut EthHdr = unsafe { ptr_at_mut::<EthHdr>(ctx, 0).ok_or(())? };
    unsafe {
        mem::swap(&mut (*eth).src, &mut (*eth).dst);
    }

    // 改写 IP 头：交换地址、重置 TTL（校验和在独立函数中计算）
    let ip_mut: *mut IpHdr = unsafe { ptr_at_mut::<IpHdr>(ctx, ETH_HDR_LEN).ok_or(())? };
    unsafe {
        mem::swap(&mut (*ip_mut).saddr, &mut (*ip_mut).daddr);
        (*ip_mut).ttl = 64;
        (*ip_mut).check = 0;
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

        // 回写 MSS 选项到 options 区域（仅 24 字节头时 option 空间为 4 字节）。
        // 使用 ptr_at_mut 的返回值作为基址：其边界证明（r>=58）随指针传播，
        // 避免 LLVM 优化删除仅用于存在性检查的边界验证。
        if new_tcp_hdr_len == 24 {
            let base =
                unsafe { ptr_at_mut::<[u8; 24]>(ctx, ETH_HDR_LEN + pc.ip_hdr_len).ok_or(())? };
            let opt = (base as *mut u8).add(20);
            unsafe {
                *opt.add(0) = TCP_OPT_MSS;
                *opt.add(1) = 4;
                let mss_val = MSS_TABLE[mss_idx as usize].1;
                *opt.add(2) = (mss_val >> 8) as u8;
                *opt.add(3) = (mss_val & 0xff) as u8;
            }
        }
    }

    // 校验和在独立栈帧中计算（bpf_csum_diff helper，避免 slice 循环占栈）
    if compute_checksums(ip_mut, tcp_mut, pc.ip_hdr_len, new_tcp_hdr_len).is_err() {
        return Err(());
    }

    Ok(())
}

/// 计算并写回 IP/TCP 校验和。保持内联以减少调用链层数（BPF 512 字节组合栈限制）。
fn compute_checksums(
    ip_mut: *mut IpHdr,
    tcp_mut: *mut TcpHdr,
    ip_hdr_len: usize,
    tcp_hdr_len: usize,
) -> Result<(), ()> {
    unsafe {
        // IP 校验和
        let ip_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            ip_mut as *mut u32,
            ip_hdr_len as u32,
            0,
        );
        if ip_sum < 0 {
            return Err(());
        }
        (*ip_mut).check = finalize_csum(ip_sum);

        // TCP 校验和 = 伪首部 + TCP 头（增量构建伪首部，参照 tcp_reset）
        let mut word: u32 = (*ip_mut).saddr;
        let mut pseudo_sum = bpf_csum_diff(core::ptr::null_mut(), 0, &mut word as *mut u32, 4, 0);
        if pseudo_sum < 0 {
            return Err(());
        }
        word = (*ip_mut).daddr;
        pseudo_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            &mut word as *mut u32,
            4,
            pseudo_sum as u32,
        );
        if pseudo_sum < 0 {
            return Err(());
        }
        // 伪首部最后一个 word：小端字节序 [0, proto, 0, len]
        word = ((6u32) << 8) | ((tcp_hdr_len as u32) << 24);
        pseudo_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            &mut word as *mut u32,
            4,
            pseudo_sum as u32,
        );
        if pseudo_sum < 0 {
            return Err(());
        }
        let tcp_sum = bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            tcp_mut as *mut u32,
            tcp_hdr_len as u32,
            pseudo_sum as u32,
        );
        if tcp_sum < 0 {
            return Err(());
        }
        (*tcp_mut).check = finalize_csum(tcp_sum);
    }

    Ok(())
}

/// 把 32 位 one's-complement 累加器折叠为最终校验和（与 tcp_reset 一致）。
#[inline(always)]
fn finalize_csum(sum: i64) -> u16 {
    let mut v = sum as u32;
    v = (v & 0xffff) + (v >> 16);
    v = (v & 0xffff) + (v >> 16);
    let r = !(v as u16);
    if r == 0 {
        0xffff
    } else {
        r
    }
}

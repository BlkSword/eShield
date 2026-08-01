#![no_std]
#![no_main]

mod blacklist;
mod icmp_flood;
mod l7_scan;
mod maps;
mod parser;
mod port_acl;
mod rate_counter;
mod rate_limit;
mod syn_cookie;
mod syn_flood;
mod tcp_reset;
mod trust;
mod udp_flood;

use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::{
    bindings::xdp_action,
    helpers::gen::{bpf_get_prandom_u32, bpf_ktime_get_ns},
    macros::xdp,
    programs::XdpContext,
};
use eshield_common::{
    project_action, rules, GeoIpKeyV4, GeoIpKeyV6, GlobalStats, IpKey, PacketSample, ProjectPolicy,
    ProjectPolicyKey, WhitelistKeyV4, WhitelistKeyV6,
};
use maps::{
    CONFIG, EVENTS, GEOIP_BLOCKED_V4, GEOIP_BLOCKED_V6, GLOBAL_STATS, PACKET_SAMPLES,
    PROJECT_POLICY, TOP_ATTACKERS, WHITELIST_V4, WHITELIST_V6,
};
use parser::{ptr_at, EthHdr, IpHdr, Ipv6Hdr, TcpHdr, ETH_HDR_LEN};

/// 哨兵值，表示当前检测模块未做出处置决定，主流程继续下一步。
const NO_ACTION: u32 = u32::MAX;

/// 把常用上下文打包成引用传递，避免每个 helper 的参数超过 BPF 寄存器上限（5 个）。
struct PacketCtx<'a> {
    ctx: &'a XdpContext,
    src: &'a IpKey,
    protocol: u8,
    sport: u16,
    dport: u16,
    ip_hdr_len: usize,
    tcp_reset_on_drop: u8,
    now_ns: u64,
    rule_id: u16,
}

#[xdp]
pub fn eshield(ctx: XdpContext) -> u32 {
    try_eshield(&ctx)
}

fn try_eshield(ctx: &XdpContext) -> u32 {
    let eth: *const EthHdr = match unsafe { ptr_at(ctx, 0) } {
        Some(p) => p,
        None => return xdp_action::XDP_PASS,
    };

    let mut src_key = IpKey::default();
    // src 引用经裸指针建立（不参与借用检查），允许 parse 直接写 pc 字段与 src_key，
    // 消除 protocol/sport/dport/ip_hdr_len 局部变量（BPF 512 字节栈限制）。
    let src_ptr = &raw mut src_key;
    let mut pc = PacketCtx {
        ctx,
        src: unsafe { &*src_ptr },
        protocol: 0,
        sport: 0,
        dport: 0,
        ip_hdr_len: 0,
        tcp_reset_on_drop: 0,
        now_ns: 0,
        rule_id: rules::UNKNOWN,
    };

    match unsafe { (*eth).proto } {
        p if p == parser::ETH_P_IP => {
            if !parse_ipv4(
                ctx,
                &mut src_key,
                &mut pc.protocol,
                &mut pc.ip_hdr_len,
                &mut pc.sport,
                &mut pc.dport,
            ) {
                return xdp_action::XDP_PASS;
            }
        }
        p if p == parser::ETH_P_IPV6 => {
            if !parse_ipv6(
                ctx,
                &mut src_key,
                &mut pc.protocol,
                &mut pc.ip_hdr_len,
                &mut pc.sport,
                &mut pc.dport,
            ) {
                return xdp_action::XDP_PASS;
            }
        }
        _ => return xdp_action::XDP_PASS,
    }

    pc.now_ns = unsafe { bpf_ktime_get_ns() };

    unsafe { with_stats(|s| s.total_packets += 1) };

    let runtime = match CONFIG.get(0) {
        Some(c) => c,
        None => return xdp_action::XDP_PASS,
    };
    pc.tcp_reset_on_drop = runtime.tcp_reset_on_drop;

    if is_whitelisted(&src_key) {
        unsafe { with_stats(|s| s.total_passed += 1) };
        trust::trust_pass(&src_key, pc.now_ns);
        return xdp_action::XDP_PASS;
    }

    let mut action: u32;

    action = check_port_acl_drop(&mut pc);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    action = check_project_policy(&mut pc);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    action = check_geoip_drop(&mut pc, runtime.geoip_enabled);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    if pc.protocol == parser::IPPROTO_TCP {
        action = check_tcp_drop(&mut pc, runtime.syn_proxy_enabled);
        if action != NO_ACTION {
            log_packet_sample(&pc, action);
            return action;
        }
    }

    action = check_udp_drop(&mut pc, runtime.udp_flood_enabled);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    action = check_icmp_drop(&mut pc, runtime.icmp_flood_enabled);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    if runtime.l7_scan_enabled != 0 {
        action = check_l7_drop(&mut pc);
        if action != NO_ACTION {
            log_packet_sample(&pc, action);
            return action;
        }
    }

    action = check_rate_limit_drop(&mut pc);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    action = check_blacklist_drop(&mut pc);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    unsafe { with_stats(|s| s.total_passed += 1) };
    trust::trust_pass(&src_key, pc.now_ns);
    xdp_action::XDP_PASS
}

/// 安全地获取并修改全局统计。
#[inline(always)]
unsafe fn with_stats(f: impl FnOnce(&mut GlobalStats)) {
    if let Some(s) = GLOBAL_STATS.get_ptr_mut(0) {
        f(&mut *s);
    }
}

#[inline(never)]
fn drop_packet(pc: &PacketCtx) -> u32 {
    unsafe { with_stats(|s| s.tcp_rst_attempt += 1) };
    trust::trust_drop(pc.src, pc.now_ns);
    // 在 eBPF 数据面统一维护高频攻击源热榜，覆盖所有丢弃路径。
    // 黑名单命中原来的 TOP_ATTACKERS 写入已移除，避免重复计数。
    let prev = unsafe { TOP_ATTACKERS.get(pc.src) }.unwrap_or(&0);
    let next = prev.saturating_add(1);
    let _ = TOP_ATTACKERS.insert(pc.src, &next, 0);
    emit_drop_event(pc);
    if pc.tcp_reset_on_drop != 0 && pc.protocol == parser::IPPROTO_TCP {
        tcp_reset::reply_tcp_rst(pc.ctx, pc.ip_hdr_len)
    } else {
        xdp_action::XDP_DROP
    }
}

#[inline(never)]
fn check_port_acl_drop(pc: &mut PacketCtx) -> u32 {
    if port_acl::check_port_acl(pc.ctx, pc.src, pc.protocol, pc.dport) {
        pc.rule_id = rules::PORT_ACL;
        unsafe {
            with_stats(|s| {
                s.total_dropped += 1;
                inc_protocol_dropped(s, pc.protocol);
            });
        }
        drop_packet(pc)
    } else {
        NO_ACTION
    }
}

/// 防护项目匹配（v0.4.6）：按 目的 IPv4 + 目的端口 + 协议 精确查表。
/// - PASS：直接放行（跳过后续防御模块，语义与白名单一致，但优先级低于端口 ACL）
/// - DROP：直接丢弃
/// - DEFEND / NONE：无特殊动作，继续全局防御流程
///
/// 控制面将 target_ips CIDR 展开为精确 IP 写入 PROJECT_POLICY；
/// 支持 any 端口（dport=0）/ any 协议（protocol=0）通配，查找时按精确度降级回退。
#[inline(never)]
fn check_project_policy(pc: &mut PacketCtx) -> u32 {
    // 快速路径：未配置防护项目时直接跳过（CONFIG Array 查询比 Hash 查询便宜得多）
    let runtime = match CONFIG.get(0) {
        Some(c) => c,
        None => return NO_ACTION,
    };
    if runtime.project_enabled == 0 {
        return NO_ACTION;
    }

    // 防护项目仅匹配 IPv4 包（src family 与包 family 一致，可作判断依据）
    let Some(eshield_common::IpFamily::Ipv4) = pc.src.family() else {
        return NO_ACTION;
    };
    // 目的 IP 从包内重读（主帧不再维护 dst_key，省 32B BPF 栈）
    let ip = match unsafe { parser::ptr_at::<IpHdr>(pc.ctx, ETH_HDR_LEN) } {
        Some(p) => p,
        None => return NO_ACTION,
    };
    let addr = unsafe { (*ip).daddr };
    let dport = pc.dport.to_be();

    // 按精确度降级查找（exact → any 协议 → any 端口 → 双 any）。
    // 复用单个栈槽构造 key，避免 4 个 key 同时占用栈空间（BPF 512 字节栈限制）。
    let mut best = ProjectPolicyKey {
        addr,
        dport: 0,
        protocol: 0,
        padding: 0,
    };
    let mut policy: Option<ProjectPolicy> = None;
    let mut idx: u64 = 0;
    while idx < 4 {
        match idx {
            0 => {
                best.dport = dport;
                best.protocol = pc.protocol;
            }
            1 => {
                best.dport = dport;
                best.protocol = 0;
            }
            2 => {
                best.dport = 0;
                best.protocol = pc.protocol;
            }
            _ => {
                best.dport = 0;
                best.protocol = 0;
            }
        }
        policy = unsafe { PROJECT_POLICY.get(&best).copied() };
        if policy.is_some() {
            break;
        }
        idx += 1;
    }
    let policy = match policy {
        Some(p) => p,
        None => return NO_ACTION,
    };

    match policy.action {
        project_action::PASS => {
            pc.rule_id = rules::PROJECT_POLICY;
            unsafe { with_stats(|s| s.total_passed += 1) };
            trust::trust_pass(pc.src, pc.now_ns);
            xdp_action::XDP_PASS
        }
        project_action::DROP => {
            pc.rule_id = rules::PROJECT_POLICY;
            unsafe {
                with_stats(|s| {
                    s.total_dropped += 1;
                    inc_protocol_dropped(s, pc.protocol);
                });
            }
            drop_packet(pc)
        }
        _ => NO_ACTION,
    }
}

#[inline(never)]
fn check_geoip_drop(pc: &mut PacketCtx, geoip_enabled: u8) -> u32 {
    if geoip_enabled != 0 && is_geoip_blocked(pc.src) {
        pc.rule_id = rules::GEOIP;
        unsafe {
            with_stats(|s| {
                s.total_dropped += 1;
                s.geoip_blocked += 1;
                inc_protocol_dropped(s, pc.protocol);
            });
        }
        drop_packet(pc)
    } else {
        NO_ACTION
    }
}

#[inline(never)]
fn check_tcp_drop(pc: &mut PacketCtx, syn_proxy_enabled: u8) -> u32 {
    if pc.src.family == (eshield_common::IpFamily::Ipv4 as u8) && syn_proxy_enabled != 0 {
        let ip_ptr = match unsafe { parser::ptr_at::<IpHdr>(pc.ctx, ETH_HDR_LEN) } {
            Some(p) => p,
            None => return xdp_action::XDP_PASS,
        };
        let tcp_ptr = match unsafe { parser::ptr_at::<TcpHdr>(pc.ctx, ETH_HDR_LEN + pc.ip_hdr_len) }
        {
            Some(t) => t,
            None => return NO_ACTION,
        };
        let pcr = syn_cookie::PacketCtxRef {
            ctx: pc.ctx,
            ip_hdr_len: pc.ip_hdr_len,
            now_ns: pc.now_ns,
        };
        let action = syn_cookie::handle_syn(&pcr, ip_ptr, tcp_ptr);
        if action != NO_ACTION {
            pc.rule_id = rules::SYN_FLOOD;
            unsafe {
                with_stats(|s| {
                    if action == xdp_action::XDP_TX {
                        s.syn_flood_blocked += 1;
                    } else {
                        s.total_dropped += 1;
                        inc_protocol_dropped(s, parser::IPPROTO_TCP);
                    }
                });
            }
            return action;
        }
        let action = syn_cookie::handle_ack(&pcr, ip_ptr, tcp_ptr);
        if action != NO_ACTION {
            unsafe { with_stats(|s| s.total_passed += 1) };
            trust::trust_pass(pc.src, pc.now_ns);
            return action;
        }
        // IPv4 + SYN Proxy 开启时，SYN Flood 检测由 handle_syn 内部完成
        //（计数一次），此处不再重复检测，避免同一 SYN 被计数两次。
        return NO_ACTION;
    }

    // SYN Flood 检测（IPv6 或 SYN Proxy 关闭时）
    if let Some(tcp) = unsafe { parser::ptr_at::<TcpHdr>(pc.ctx, ETH_HDR_LEN + pc.ip_hdr_len) } {
        let tcp_flags = unsafe { (*tcp).flags() };
        if syn_flood::handle_syn_flood(pc.src, tcp_flags, pc.now_ns) {
            pc.rule_id = rules::SYN_FLOOD;
            unsafe {
                with_stats(|s| {
                    s.total_dropped += 1;
                    s.syn_flood_blocked += 1;
                    inc_protocol_dropped(s, parser::IPPROTO_TCP);
                });
            }
            return drop_packet(pc);
        }
    }
    NO_ACTION
}

#[inline(never)]
fn check_udp_drop(pc: &mut PacketCtx, udp_flood_enabled: u8) -> u32 {
    if pc.protocol == parser::IPPROTO_UDP
        && udp_flood_enabled != 0
        && udp_flood::handle_udp_flood(pc.ctx, pc.src, pc.now_ns)
    {
        pc.rule_id = rules::UDP_FLOOD;
        unsafe {
            with_stats(|s| {
                s.total_dropped += 1;
                s.udp_flood_blocked += 1;
                inc_protocol_dropped(s, pc.protocol);
            });
        }
        return drop_packet(pc);
    }
    NO_ACTION
}

#[inline(never)]
fn check_icmp_drop(pc: &mut PacketCtx, icmp_flood_enabled: u8) -> u32 {
    if (pc.protocol == parser::IPPROTO_ICMP || pc.protocol == parser::IPPROTO_ICMPV6)
        && icmp_flood_enabled != 0
        && icmp_flood::handle_icmp_flood(pc.ctx, pc.src, pc.now_ns, pc.protocol)
    {
        pc.rule_id = rules::ICMP_FLOOD;
        unsafe {
            with_stats(|s| {
                s.total_dropped += 1;
                s.icmp_flood_blocked += 1;
                inc_protocol_dropped(s, pc.protocol);
            });
        }
        return drop_packet(pc);
    }
    NO_ACTION
}

#[inline(never)]
fn check_l7_drop(pc: &mut PacketCtx) -> u32 {
    if l7_scan::scan(pc.ctx, pc.src, pc.ip_hdr_len, pc.protocol, pc.dport) {
        pc.rule_id = rules::L7_PATTERN;
        unsafe {
            with_stats(|s| {
                s.total_dropped += 1;
                s.l7_blocked += 1;
                inc_protocol_dropped(s, pc.protocol);
            });
        }
        return drop_packet(pc);
    }
    NO_ACTION
}

#[inline(never)]
fn check_rate_limit_drop(pc: &mut PacketCtx) -> u32 {
    if rate_limit::check_rate_limit(pc.src, pc.now_ns) {
        pc.rule_id = rules::RATE_LIMIT;
        unsafe {
            with_stats(|s| {
                s.total_dropped += 1;
                s.rate_limited += 1;
                inc_protocol_dropped(s, pc.protocol);
            });
        }
        return drop_packet(pc);
    }
    NO_ACTION
}

#[inline(never)]
fn check_blacklist_drop(pc: &mut PacketCtx) -> u32 {
    if blacklist::is_blacklisted(pc.src, pc.now_ns) {
        pc.rule_id = rules::BLACKLIST;
        unsafe {
            with_stats(|s| {
                s.total_dropped += 1;
                s.blacklist_blocked += 1;
                inc_protocol_dropped(s, pc.protocol);
            });
        }
        return drop_packet(pc);
    }
    NO_ACTION
}

#[inline(always)]
fn inc_protocol_dropped(stats: &mut GlobalStats, protocol: u8) {
    match protocol {
        parser::IPPROTO_TCP => stats.tcp_dropped += 1,
        parser::IPPROTO_UDP => stats.udp_dropped += 1,
        parser::IPPROTO_ICMP | parser::IPPROTO_ICMPV6 => stats.icmp_dropped += 1,
        _ => stats.other_dropped += 1,
    }
}

fn parse_ipv4(
    ctx: &XdpContext,
    src: &mut IpKey,
    protocol: &mut u8,
    ip_hdr_len: &mut usize,
    sport: &mut u16,
    dport: &mut u16,
) -> bool {
    let ip: *const IpHdr = match unsafe { ptr_at(ctx, ETH_HDR_LEN) } {
        Some(p) => p,
        None => return false,
    };
    let len = ((unsafe { (*ip).ver_ihl } & 0x0f) as usize) * 4;
    if len < parser::IP_HDR_LEN {
        return false;
    }

    let saddr = unsafe { (*ip).saddr };
    *src = IpKey::from_ipv4(saddr.to_ne_bytes());
    *protocol = unsafe { (*ip).proto };
    *ip_hdr_len = len;
    if !read_ports(ctx, ETH_HDR_LEN + len, *protocol, sport, dport) {
        return false;
    }
    true
}

fn parse_ipv6(
    ctx: &XdpContext,
    src: &mut IpKey,
    protocol: &mut u8,
    ip_hdr_len: &mut usize,
    sport: &mut u16,
    dport: &mut u16,
) -> bool {
    let ip: *const Ipv6Hdr = match unsafe { ptr_at(ctx, ETH_HDR_LEN) } {
        Some(p) => p,
        None => return false,
    };
    *src = IpKey::from_ipv6(unsafe { (*ip).saddr });
    *protocol = unsafe { (*ip).next_header };
    *ip_hdr_len = parser::IPV6_HDR_LEN;
    if !read_ports(
        ctx,
        ETH_HDR_LEN + parser::IPV6_HDR_LEN,
        *protocol,
        sport,
        dport,
    ) {
        return false;
    }
    true
}

fn read_ports(
    ctx: &XdpContext,
    transport_offset: usize,
    protocol: u8,
    sport: &mut u16,
    dport: &mut u16,
) -> bool {
    match protocol {
        parser::IPPROTO_TCP => {
            let tcp: *const TcpHdr = match unsafe { ptr_at(ctx, transport_offset) } {
                Some(p) => p,
                None => return false,
            };
            *sport = u16::from_be(unsafe { (*tcp).source });
            *dport = u16::from_be(unsafe { (*tcp).dest });
        }
        parser::IPPROTO_UDP => {
            let udp: *const parser::UdpHdr = match unsafe { ptr_at(ctx, transport_offset) } {
                Some(p) => p,
                None => return false,
            };
            *sport = u16::from_be(unsafe { (*udp).source });
            *dport = u16::from_be(unsafe { (*udp).dest });
        }
        _ => {
            *sport = 0;
            *dport = 0;
        }
    }
    true
}

/// 按采样率将被丢弃/放行的包元数据写入 PACKET_SAMPLES Ring Buffer。
/// 仅由主流程的提前返回路径调用（当前仅 DROP 与防护项目 PASS）；action 标记 0=drop / 1=pass。
#[inline(never)]
fn log_packet_sample(pc: &PacketCtx, action: u32) {
    let runtime = match CONFIG.get(0) {
        Some(c) => c,
        None => return,
    };
    if runtime.packet_log_enabled == 0 || runtime.packet_log_sample_rate == 0 {
        return;
    }
    if unsafe { bpf_get_prandom_u32() } % runtime.packet_log_sample_rate as u32 != 0 {
        return;
    }

    let mut entry = match PACKET_SAMPLES.reserve::<PacketSample>(0) {
        Some(e) => e,
        None => return,
    };

    let data = pc.ctx.data();
    let data_end = pc.ctx.data_end();
    let packet_len = if data_end > data {
        (data_end - data) as u16
    } else {
        0
    };
    // 最多复制 64 字节；短包按实际长度复制。
    let copy_len = if packet_len >= 64 { 64 } else { packet_len };

    let event = entry.as_mut_ptr() as *mut PacketSample;
    unsafe {
        // 先清零 payload 区域，避免残留旧数据
        // while 循环：避免 for-range 迭代器生成 u32→u64 零扩展（<<=）指令，
        // 该模式在部分内核的 verifier 上被拒绝（pointer arithmetic with <<=）。
        let mut i: u64 = 0;
        while i < 64 {
            (*event).payload_sample[i as usize] = 0;
            i += 1;
        }

        (*event).timestamp_ns = pc.now_ns;
        (*event).src_ip = pc.src.addr;
        // 目的 IP 从包内重读（主帧不维护 dst_key）
        let dst_ip = match pc.src.family() {
            Some(eshield_common::IpFamily::Ipv4) => {
                match unsafe { parser::ptr_at::<IpHdr>(pc.ctx, ETH_HDR_LEN) } {
                    Some(ip) => {
                        let mut a = [0u8; 16];
                        a[12..16].copy_from_slice(&(*ip).daddr.to_ne_bytes());
                        a
                    }
                    None => [0u8; 16],
                }
            }
            Some(eshield_common::IpFamily::Ipv6) => {
                match unsafe { parser::ptr_at::<Ipv6Hdr>(pc.ctx, ETH_HDR_LEN) } {
                    Some(ip) => (*ip).daddr,
                    None => [0u8; 16],
                }
            }
            None => [0u8; 16],
        };
        (*event).dst_ip = dst_ip;
        (*event).family = pc.src.family;
        (*event).protocol = pc.protocol;
        (*event).src_port = pc.sport;
        (*event).dst_port = pc.dport;
        (*event).action = if action == xdp_action::XDP_PASS { 1 } else { 0 };
        (*event).rule_id = pc.rule_id;
        (*event).packet_len = packet_len;
        (*event).payload_bytes = copy_len as u8;

        // 在 verifier 可见的边界检查之后按 copy_len 复制
        if data + 64 <= data_end {
            let src_ptr = data as *const u8;
            let mut j: u64 = 0;
            while j < copy_len as u64 {
                (*event).payload_sample[j as usize] = *src_ptr.add(j as usize);
                j += 1;
            }
        }
    }
    entry.submit(0);
}

fn is_whitelisted(src: &IpKey) -> bool {
    match src.family() {
        Some(eshield_common::IpFamily::Ipv4) => {
            let key = LpmKey::new(
                32,
                WhitelistKeyV4 {
                    addr: src.ipv4().to_be(),
                },
            );
            WHITELIST_V4.get(&key).is_some()
        }
        Some(eshield_common::IpFamily::Ipv6) => {
            let key = LpmKey::new(128, WhitelistKeyV6 { addr: src.addr });
            WHITELIST_V6.get(&key).is_some()
        }
        None => false,
    }
}

fn is_geoip_blocked(src: &IpKey) -> bool {
    match src.family() {
        Some(eshield_common::IpFamily::Ipv4) => {
            let key = LpmKey::new(
                32,
                GeoIpKeyV4 {
                    addr: src.ipv4().to_be(),
                },
            );
            GEOIP_BLOCKED_V4.get(&key).is_some()
        }
        Some(eshield_common::IpFamily::Ipv6) => {
            let key = LpmKey::new(128, GeoIpKeyV6 { addr: src.addr });
            GEOIP_BLOCKED_V6.get(&key).is_some()
        }
        None => false,
    }
}

/// 独立栈帧：避免 RingBuf 操作局部与 drop_packet 叠加（BPF 512 字节栈限制）。
#[inline(never)]
fn emit_drop_event(pc: &PacketCtx) {
    if let Some(mut entry) = EVENTS.reserve::<eshield_common::DropEvent>(0) {
        let event = entry.as_mut_ptr() as *mut eshield_common::DropEvent;
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).src_ip = pc.src.addr;
            (*event).family = pc.src.family;
            (*event).protocol = pc.protocol;
            (*event).rule_id = pc.rule_id;
            (*event).dst_port = pc.dport;
        }
        entry.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

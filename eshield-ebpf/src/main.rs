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
    rules, GeoIpKeyV4, GeoIpKeyV6, GlobalStats, IpKey, PacketSample, WhitelistKeyV4, WhitelistKeyV6,
};
use maps::{
    CONFIG, EVENTS, GEOIP_BLOCKED_V4, GEOIP_BLOCKED_V6, GLOBAL_STATS, PACKET_SAMPLES, WHITELIST_V4,
    WHITELIST_V6,
};
use parser::{ptr_at, EthHdr, IpHdr, Ipv6Hdr, TcpHdr, ETH_HDR_LEN};

/// 哨兵值，表示当前检测模块未做出处置决定，主流程继续下一步。
const NO_ACTION: u32 = u32::MAX;

/// 把常用上下文打包成引用传递，避免每个 helper 的参数超过 BPF 寄存器上限（5 个）。
struct PacketCtx<'a> {
    ctx: &'a XdpContext,
    src: &'a IpKey,
    dst: &'a IpKey,
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
    let eth_proto = unsafe { (*eth).proto };

    let mut src_key = IpKey::default();
    let mut dst_key = IpKey::default();
    let mut protocol: u8 = 0;
    let mut ip_hdr_len: usize = 0;
    let mut sport: u16 = 0;
    let mut dport: u16 = 0;

    if eth_proto == parser::ETH_P_IP {
        if !parse_ipv4(
            ctx,
            &mut src_key,
            &mut dst_key,
            &mut protocol,
            &mut ip_hdr_len,
            &mut sport,
            &mut dport,
        ) {
            return xdp_action::XDP_PASS;
        }
    } else if eth_proto == parser::ETH_P_IPV6 {
        if !parse_ipv6(
            ctx,
            &mut src_key,
            &mut dst_key,
            &mut protocol,
            &mut ip_hdr_len,
            &mut sport,
            &mut dport,
        ) {
            return xdp_action::XDP_PASS;
        }
    } else {
        return xdp_action::XDP_PASS;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };

    unsafe { with_stats(|s| s.total_packets += 1) };

    let runtime = match CONFIG.get(0) {
        Some(c) => c,
        None => return xdp_action::XDP_PASS,
    };

    let mut pc = PacketCtx {
        ctx,
        src: &src_key,
        dst: &dst_key,
        protocol,
        sport,
        dport,
        ip_hdr_len,
        tcp_reset_on_drop: runtime.tcp_reset_on_drop,
        now_ns,
        rule_id: rules::UNKNOWN,
    };

    if is_whitelisted(&src_key) {
        unsafe { with_stats(|s| s.total_passed += 1) };
        trust::trust_pass(&src_key, now_ns);
        return xdp_action::XDP_PASS;
    }

    let mut action: u32;

    action = check_port_acl_drop(&mut pc);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    action = check_geoip_drop(&mut pc, runtime.geoip_enabled);
    if action != NO_ACTION {
        log_packet_sample(&pc, action);
        return action;
    }

    if protocol == parser::IPPROTO_TCP {
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
    trust::trust_pass(&src_key, now_ns);
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
        emit_geoip_event(pc.ctx, pc.src, pc.protocol, pc.dport);
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
        let action = syn_cookie::handle_syn(pc.ctx, ip_ptr, pc.ip_hdr_len);
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
        let action = syn_cookie::handle_ack(pc.ctx, ip_ptr, pc.ip_hdr_len);
        if action != NO_ACTION {
            unsafe { with_stats(|s| s.total_passed += 1) };
            trust::trust_pass(pc.src, pc.now_ns);
            return action;
        }
    }

    // SYN Flood 检测始终运行（与 SYN Cookie 代理互不排斥）。
    if let Some(tcp) = unsafe { parser::ptr_at::<TcpHdr>(pc.ctx, ETH_HDR_LEN + pc.ip_hdr_len) } {
        let tcp_flags = unsafe { (*tcp).flags() };
        if syn_flood::handle_syn_flood(pc.ctx, pc.src, tcp_flags, pc.now_ns) {
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
    dst: &mut IpKey,
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
    let daddr = unsafe { (*ip).daddr };
    *src = IpKey::from_ipv4(saddr.to_ne_bytes());
    *dst = IpKey::from_ipv4(daddr.to_ne_bytes());
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
    dst: &mut IpKey,
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
    *dst = IpKey::from_ipv6(unsafe { (*ip).daddr });
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

/// 按采样率将被丢弃的包元数据写入 PACKET_SAMPLES Ring Buffer。
/// 仅由 DROP 路径调用；action 仅用于标记 0=drop，不直接作为 XDP action 返回。
#[inline(never)]
fn log_packet_sample(pc: &PacketCtx, _action: u32) {
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
        for i in 0..64 {
            (*event).payload_sample[i] = 0;
        }

        (*event).timestamp_ns = pc.now_ns;
        (*event).src_ip = pc.src.addr;
        (*event).dst_ip = pc.dst.addr;
        (*event).family = pc.src.family;
        (*event).protocol = pc.protocol;
        (*event).src_port = pc.sport;
        (*event).dst_port = pc.dport;
        (*event).action = 0; // 0 = drop
        (*event).rule_id = pc.rule_id;
        (*event).packet_len = packet_len;
        (*event).payload_bytes = copy_len as u8;

        // 在 verifier 可见的边界检查之后按 copy_len 复制
        if data + 64 <= data_end {
            let src_ptr = data as *const u8;
            for i in 0..copy_len {
                (*event).payload_sample[i as usize] = *src_ptr.add(i as usize);
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

fn emit_geoip_event(_ctx: &XdpContext, src: &IpKey, protocol: u8, dst_port: u16) {
    if let Some(mut entry) = EVENTS.reserve::<eshield_common::DropEvent>(0) {
        let event = entry.as_mut_ptr() as *mut eshield_common::DropEvent;
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).src_ip = src.addr;
            (*event).family = src.family;
            (*event).protocol = protocol;
            (*event).rule_id = eshield_common::rules::GEOIP;
            (*event).dst_port = dst_port;
        }
        entry.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

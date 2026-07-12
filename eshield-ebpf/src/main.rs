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
    bindings::xdp_action, helpers::gen::bpf_ktime_get_ns, macros::xdp, programs::XdpContext,
};
use eshield_common::{
    GeoIpKeyV4, GeoIpKeyV6, GlobalStats, IpKey, WhitelistKeyV4, WhitelistKeyV6,
};
use maps::{
    CONFIG, EVENTS, GEOIP_BLOCKED_V4, GEOIP_BLOCKED_V6, GLOBAL_STATS, WHITELIST_V4, WHITELIST_V6,
};
use parser::{ptr_at, EthHdr, IpHdr, Ipv6Hdr, TcpHdr, ETH_HDR_LEN};

/// 哨兵值，表示当前检测模块未做出处置决定，主流程继续下一步。
const NO_ACTION: u32 = u32::MAX;

/// 把常用上下文打包成引用传递，避免每个 helper 的参数超过 BPF 寄存器上限（5 个）。
struct PacketCtx<'a> {
    ctx: &'a XdpContext,
    src: &'a IpKey,
    protocol: u8,
    dport: u16,
    ip_hdr_len: usize,
    tcp_reset_on_drop: u8,
    now_ns: u64,
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
    let mut protocol: u8 = 0;
    let mut ip_hdr_len: usize = 0;
    let mut dport: u16 = 0;

    if eth_proto == parser::ETH_P_IP {
        if !parse_ipv4(ctx, &mut src_key, &mut protocol, &mut ip_hdr_len, &mut dport) {
            return xdp_action::XDP_PASS;
        }
    } else if eth_proto == parser::ETH_P_IPV6 {
        if !parse_ipv6(ctx, &mut src_key, &mut protocol, &mut ip_hdr_len, &mut dport) {
            return xdp_action::XDP_PASS;
        }
    } else {
        return xdp_action::XDP_PASS;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };

    unsafe { with_stats(|s| s.total_packets += 1) };

    if is_whitelisted(&src_key) {
        unsafe { with_stats(|s| s.total_passed += 1) };
        trust::trust_pass(&src_key, now_ns);
        return xdp_action::XDP_PASS;
    }

    let runtime = match CONFIG.get(0) {
        Some(c) => c,
        None => return xdp_action::XDP_PASS,
    };

    let pc = PacketCtx {
        ctx,
        src: &src_key,
        protocol,
        dport,
        ip_hdr_len,
        tcp_reset_on_drop: runtime.tcp_reset_on_drop,
        now_ns,
    };

    let mut action: u32;

    action = check_port_acl_drop(&pc);
    if action != NO_ACTION {
        return action;
    }

    action = check_geoip_drop(&pc, runtime.geoip_enabled);
    if action != NO_ACTION {
        return action;
    }

    if protocol == parser::IPPROTO_TCP {
        action = check_tcp_drop(&pc, runtime.syn_proxy_enabled);
        if action != NO_ACTION {
            return action;
        }
    }

    action = check_udp_drop(&pc, runtime.udp_flood_enabled);
    if action != NO_ACTION {
        return action;
    }

    action = check_icmp_drop(&pc, runtime.icmp_flood_enabled);
    if action != NO_ACTION {
        return action;
    }

    if runtime.l7_scan_enabled != 0 {
        action = check_l7_drop(&pc);
        if action != NO_ACTION {
            return action;
        }
    }

    action = check_rate_limit_drop(&pc);
    if action != NO_ACTION {
        return action;
    }

    action = check_blacklist_drop(&pc);
    if action != NO_ACTION {
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
fn check_port_acl_drop(pc: &PacketCtx) -> u32 {
    if port_acl::check_port_acl(pc.ctx, pc.src, pc.protocol, pc.dport) {
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
fn check_geoip_drop(pc: &PacketCtx, geoip_enabled: u8) -> u32 {
    if geoip_enabled != 0 && is_geoip_blocked(pc.src) {
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
fn check_tcp_drop(pc: &PacketCtx, syn_proxy_enabled: u8) -> u32 {
    if pc.src.family == (eshield_common::IpFamily::Ipv4 as u8) && syn_proxy_enabled != 0 {
        let ip_ptr = match unsafe { parser::ptr_at::<IpHdr>(pc.ctx, ETH_HDR_LEN) } {
            Some(p) => p,
            None => return xdp_action::XDP_PASS,
        };
        let action = syn_cookie::handle_syn(pc.ctx, ip_ptr, pc.ip_hdr_len);
        if action != NO_ACTION {
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
fn check_udp_drop(pc: &PacketCtx, udp_flood_enabled: u8) -> u32 {
    if pc.protocol == parser::IPPROTO_UDP
        && udp_flood_enabled != 0
        && udp_flood::handle_udp_flood(pc.ctx, pc.src, pc.now_ns)
    {
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
fn check_icmp_drop(pc: &PacketCtx, icmp_flood_enabled: u8) -> u32 {
    if (pc.protocol == parser::IPPROTO_ICMP || pc.protocol == parser::IPPROTO_ICMPV6)
        && icmp_flood_enabled != 0
        && icmp_flood::handle_icmp_flood(pc.ctx, pc.src, pc.now_ns, pc.protocol)
    {
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
fn check_l7_drop(pc: &PacketCtx) -> u32 {
    if l7_scan::scan(pc.ctx, pc.src, pc.ip_hdr_len, pc.protocol, pc.dport) {
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
fn check_rate_limit_drop(pc: &PacketCtx) -> u32 {
    if rate_limit::check_rate_limit(pc.src, pc.now_ns) {
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
fn check_blacklist_drop(pc: &PacketCtx) -> u32 {
    if blacklist::is_blacklisted(pc.src, pc.now_ns) {
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
    if !read_dport(ctx, ETH_HDR_LEN + len, *protocol, dport) {
        return false;
    }
    true
}

fn parse_ipv6(
    ctx: &XdpContext,
    src: &mut IpKey,
    protocol: &mut u8,
    ip_hdr_len: &mut usize,
    dport: &mut u16,
) -> bool {
    let ip: *const Ipv6Hdr = match unsafe { ptr_at(ctx, ETH_HDR_LEN) } {
        Some(p) => p,
        None => return false,
    };
    *src = IpKey::from_ipv6(unsafe { (*ip).saddr });
    *protocol = unsafe { (*ip).next_header };
    *ip_hdr_len = parser::IPV6_HDR_LEN;
    if !read_dport(ctx, ETH_HDR_LEN + parser::IPV6_HDR_LEN, *protocol, dport) {
        return false;
    }
    true
}

fn read_dport(ctx: &XdpContext, transport_offset: usize, protocol: u8, out: &mut u16) -> bool {
    match protocol {
        parser::IPPROTO_TCP => {
            let tcp: *const TcpHdr = match unsafe { ptr_at(ctx, transport_offset) } {
                Some(p) => p,
                None => return false,
            };
            *out = u16::from_be(unsafe { (*tcp).dest });
        }
        parser::IPPROTO_UDP => {
            let udp: *const parser::UdpHdr = match unsafe { ptr_at(ctx, transport_offset) } {
                Some(p) => p,
                None => return false,
            };
            *out = u16::from_be(unsafe { (*udp).dest });
        }
        _ => *out = 0,
    }
    true
}

fn is_whitelisted(src: &IpKey) -> bool {
    match src.family() {
        Some(eshield_common::IpFamily::Ipv4) => {
            let key = LpmKey::new(32, WhitelistKeyV4 { addr: src.ipv4().to_be() });
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
            let key = LpmKey::new(32, GeoIpKeyV4 { addr: src.ipv4().to_be() });
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

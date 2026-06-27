#![no_std]
#![no_main]

mod blacklist;
mod challenge;
mod icmp_flood;
mod l7_scan;
mod maps;
mod parser;
mod port_acl;
mod rate_limit;
mod syn_cookie;
mod syn_flood;
mod udp_flood;
mod waf;

use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::{
    bindings::xdp_action, helpers::gen::bpf_ktime_get_ns, macros::xdp, programs::XdpContext,
};
use aya_log_ebpf::debug;
use eshield_common::{GeoIpKeyV4, GeoIpKeyV6, IpKey, WhitelistKeyV4, WhitelistKeyV6};
use maps::{CONFIG, EVENTS, GEOIP_BLOCKED_V4, GEOIP_BLOCKED_V6, GLOBAL_STATS, WHITELIST_V4, WHITELIST_V6};
use parser::{ptr_at, EthHdr, IpHdr, Ipv6Hdr, TcpHdr, UdpHdr, ETH_HDR_LEN};

#[xdp]
pub fn eshield(ctx: XdpContext) -> u32 {
    match try_eshield(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_eshield(ctx: &XdpContext) -> Result<u32, ()> {
    // 1. 解析以太网头
    let eth: *const EthHdr = unsafe { ptr_at(ctx, 0).ok_or(())? };
    let eth_proto = unsafe { (*eth).proto };

    let (src_key, protocol, ip_hdr_len, dport) = if eth_proto == parser::ETH_P_IP {
        parse_ipv4(ctx)?
    } else if eth_proto == parser::ETH_P_IPV6 {
        parse_ipv6(ctx)?
    } else {
        // 非 IPv4/IPv6，直接放行
        return Ok(xdp_action::XDP_PASS);
    };

    let now_ns = unsafe { bpf_ktime_get_ns() };

    // 2. 更新全局统计
    unsafe {
        if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
            let stats = &mut *stats;
            stats.total_packets += 1;
        }
    }

    // 3. 白名单检查（CIDR）
    if is_whitelisted(&src_key) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                (*stats).total_passed += 1;
            }
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // 4. 端口/协议 ACL
    if port_acl::check_port_acl(ctx, &src_key, protocol, dport) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
            }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // 5. 获取运行时配置
    let runtime = match CONFIG.get(0) {
        Some(c) => *c,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // 计算 TCP payload 偏移与长度（供 L7 / WAF 使用）。
    // 使用 ctx.data_end() 与 ctx.data() 的差值计算实际 payload 长度，
    // 避免依赖 IP total_len 的字节序转换，同时 verifier 可以证明有界。
    let data_start = ctx.data();
    let data_end = ctx.data_end();
    let mut payload_offset = 0usize;
    let mut payload_len = 0usize;
    if protocol == parser::IPPROTO_TCP {
        if let Some(tcp) = unsafe { ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len) } {
            let tcp_hdr_len = unsafe { (*tcp).doff() as usize } * 4;
            payload_offset = ETH_HDR_LEN + ip_hdr_len + tcp_hdr_len;
            if data_start + payload_offset < data_end {
                payload_len = data_end - (data_start + payload_offset);
            }
        }
    }

    // 6. Challenge 临时白名单：已通过挑战的 IP 直接放行
    if runtime.challenge_enabled != 0 && challenge::is_allowed(&src_key, now_ns) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                (*stats).total_passed += 1;
            }
        }
        return Ok(xdp_action::XDP_PASS);
    }

    if runtime.ebpf_debug != 0 {
        if src_key.family == (eshield_common::IpFamily::Ipv4 as u8) {
            debug!(
                ctx,
                "eshield packet src={:i} proto={} dport={} action=begin",
                src_key.ipv4(),
                protocol as u32,
                dport as u32
            );
        } else {
            debug!(
                ctx,
                "eshield packet src={:i} proto={} dport={} action=begin",
                src_key.addr,
                protocol as u32,
                dport as u32
            );
        }
    }

    // 6. GeoIP/ASN 封禁（LPM Trie CIDR 匹配）
    let geoip_blocked = is_geoip_blocked(&src_key);
    if runtime.ebpf_debug != 0 {
        debug!(
            ctx,
            "geoip check enabled={} blocked={}",
            runtime.geoip_enabled as u32,
            geoip_blocked as u32
        );
    }
    if runtime.geoip_enabled != 0 && geoip_blocked {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
                stats.geoip_blocked += 1;
            }
        }
        emit_geoip_event(ctx, &src_key, protocol);
        return Ok(xdp_action::XDP_DROP);
    }

    // 7. SYN Cookie 代理（仅 IPv4 TCP） / SYN Flood 检测
    if protocol == parser::IPPROTO_TCP {
        if src_key.family == (eshield_common::IpFamily::Ipv4 as u8)
            && runtime.syn_proxy_enabled != 0
        {
            // SYN Cookie 代理：对 SYN 回复 SYN-ACK，对合法 ACK 放行
            if let Some(action) = syn_cookie::handle_syn(
                ctx,
                unsafe { parser::ptr_at::<IpHdr>(ctx, ETH_HDR_LEN).ok_or(())? },
                ip_hdr_len,
            ) {
                unsafe {
                    if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                        let stats = &mut *stats;
                        if action == xdp_action::XDP_TX {
                            stats.syn_flood_blocked += 1;
                        } else {
                            stats.total_dropped += 1;
                        }
                    }
                }
                return Ok(action);
            }
            if let Some(action) = syn_cookie::handle_ack(
                ctx,
                unsafe { parser::ptr_at::<IpHdr>(ctx, ETH_HDR_LEN).ok_or(())? },
                ip_hdr_len,
            ) {
                unsafe {
                    if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                        (*stats).total_passed += 1;
                    }
                }
                return Ok(action);
            }
        } else if let Some(tcp) = unsafe { parser::ptr_at::<TcpHdr>(ctx, ETH_HDR_LEN + ip_hdr_len) }
        {
            let tcp_flags = unsafe { (*tcp).flags() };
            if syn_flood::handle_syn_flood(ctx, &src_key, tcp_flags, now_ns) {
                unsafe {
                    if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                        let stats = &mut *stats;
                        stats.total_dropped += 1;
                        stats.syn_flood_blocked += 1;
                    }
                }
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    // 7. UDP Flood 检测
    if protocol == parser::IPPROTO_UDP && udp_flood::handle_udp_flood(ctx, &src_key, now_ns) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
                stats.udp_flood_blocked += 1;
            }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // 8. ICMP/ICMPv6 Flood 检测
    if (protocol == parser::IPPROTO_ICMP || protocol == parser::IPPROTO_ICMPV6)
        && icmp_flood::handle_icmp_flood(ctx, &src_key, now_ns, protocol)
    {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
                stats.icmp_flood_blocked += 1;
            }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // 9. L7 轻量指纹扫描（TCP 载荷前 64 字节）
    if l7_scan::scan(ctx, &src_key, ip_hdr_len, protocol) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
                stats.l7_blocked += 1;
            }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // 10. HTTP WAF 规则引擎（TCP 首包解析）
    if protocol == parser::IPPROTO_TCP
        && runtime.waf_enabled != 0
        && payload_len > 0
    {
        if let Some(action) = waf::check(ctx, &src_key, payload_offset) {
            if action == eshield_common::WafAction::Drop as u8 {
                return Ok(xdp_action::XDP_DROP);
            }
            // Challenge 动作同样先 DROP，用户需主动访问 challenge 页面完成验证后进入临时白名单。
            if action == eshield_common::WafAction::Challenge as u8 {
                return Ok(xdp_action::XDP_DROP);
            }
            // log 动作不拦截，继续后续检查
        }
    }

    // 11. 速率限制检查（触发则加入黑名单并 DROP）
    if rate_limit::check_rate_limit(&src_key, now_ns) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
                stats.rate_limited += 1;
            }
        }
        rate_limit::emit_rate_limit_event(ctx, &src_key, protocol);
        return Ok(xdp_action::XDP_DROP);
    }

    // 11. 黑名单检查
    let blacklisted = blacklist::is_blacklisted(&src_key, now_ns);
    if runtime.ebpf_debug != 0 {
        debug!(ctx, "blacklist check family={} last_octet={} result={}", src_key.family as u32, src_key.addr[15] as u32, blacklisted as u32);
    }
    if blacklisted {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
            }
        }
        blacklist::emit_blacklist_event(ctx, &src_key, protocol);
        return Ok(xdp_action::XDP_DROP);
    }

    // 12. 默认放行
    unsafe {
        if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
            (*stats).total_passed += 1;
        }
    }
    Ok(xdp_action::XDP_PASS)
}

fn parse_ipv4(ctx: &XdpContext) -> Result<(IpKey, u8, usize, u16), ()> {
    let ip: *const IpHdr = unsafe { ptr_at(ctx, ETH_HDR_LEN).ok_or(())? };
    let ip_hdr_len = ((unsafe { (*ip).ver_ihl } & 0x0f) as usize) * 4;
    if ip_hdr_len < parser::IP_HDR_LEN {
        return Ok((IpKey::default(), 0, 0, 0));
    }

    let saddr = unsafe { (*ip).saddr };
    let src_key = IpKey::from_ipv4(saddr.to_ne_bytes());
    let protocol = unsafe { (*ip).proto };
    let dport = read_dport(ctx, ETH_HDR_LEN + ip_hdr_len, protocol)?;

    Ok((src_key, protocol, ip_hdr_len, dport))
}

fn parse_ipv6(ctx: &XdpContext) -> Result<(IpKey, u8, usize, u16), ()> {
    let ip: *const Ipv6Hdr = unsafe { ptr_at(ctx, ETH_HDR_LEN).ok_or(())? };
    let src_key = IpKey::from_ipv6(unsafe { (*ip).saddr });
    let protocol = unsafe { (*ip).next_header };
    let ip_hdr_len = parser::IPV6_HDR_LEN;
    let dport = read_dport(ctx, ETH_HDR_LEN + ip_hdr_len, protocol)?;

    Ok((src_key, protocol, ip_hdr_len, dport))
}

fn read_dport(ctx: &XdpContext, transport_offset: usize, protocol: u8) -> Result<u16, ()> {
    match protocol {
        parser::IPPROTO_TCP => {
            let tcp: *const TcpHdr = unsafe { ptr_at(ctx, transport_offset).ok_or(())? };
            Ok(u16::from_be(unsafe { (*tcp).dest }))
        }
        parser::IPPROTO_UDP => {
            let udp: *const UdpHdr = unsafe { ptr_at(ctx, transport_offset).ok_or(())? };
            Ok(u16::from_be(unsafe { (*udp).dest }))
        }
        _ => Ok(0),
    }
}

fn is_whitelisted(src: &IpKey) -> bool {
    match src.family() {
        Some(eshield_common::IpFamily::Ipv4) => {
            // LPM Trie data 必须按网络字节序存储/匹配。
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
            // LPM Trie data 必须按网络字节序存储/匹配。
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

fn emit_geoip_event(ctx: &XdpContext, src: &IpKey, protocol: u8) {
    if let Some(mut entry) = EVENTS.reserve::<eshield_common::DropEvent>(0) {
        let event = unsafe { entry.as_mut_ptr() as *mut eshield_common::DropEvent };
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).src_ip = src.addr;
            (*event).family = src.family;
            (*event).protocol = protocol;
            (*event).rule_id = eshield_common::rules::GEOIP;
        }
        entry.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#![no_std]
#![no_main]

mod blacklist;
mod l7_scan;
mod maps;
mod parser;
mod rate_limit;
mod syn_cookie;
mod syn_flood;

use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::{
    bindings::xdp_action, helpers::gen::bpf_ktime_get_ns, macros::xdp, programs::XdpContext,
};
use eshield_common::WhitelistKey;
use maps::{CONFIG, GLOBAL_STATS, WHITELIST};
use parser::{ptr_at, EthHdr, IpHdr};

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
    if eth_proto != u16::to_be(0x0800) {
        // 非 IPv4，直接放行
        return Ok(xdp_action::XDP_PASS);
    }

    // 2. 解析 IP 头
    let ip: *const IpHdr = unsafe { ptr_at(ctx, parser::ETH_HDR_LEN).ok_or(())? };
    let ip_hdr_len = ((unsafe { (*ip).ver_ihl } & 0x0f) as usize) * 4;
    if ip_hdr_len < parser::IP_HDR_LEN {
        return Ok(xdp_action::XDP_DROP);
    }

    let saddr = unsafe { (*ip).saddr };
    // saddr 是网络字节序；Map 中统一按主机字节序存储 IP 键
    let saddr_host = u32::from_be(saddr);
    let protocol = unsafe { (*ip).proto };
    let now_ns = unsafe { bpf_ktime_get_ns() };

    // 3. 更新全局统计
    unsafe {
        if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
            let stats = &mut *stats;
            stats.total_packets += 1;
        }
    }

    // 4. 白名单检查（CIDR）
    if is_whitelisted(saddr_host) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                (*stats).total_passed += 1;
            }
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // 5. SYN Cookie 代理 / SYN Flood 检测
    let runtime = match CONFIG.get(0) {
        Some(c) => *c,
        None => return Ok(xdp_action::XDP_PASS),
    };

    let mut tcp_hdr_len: usize = 0;
    if protocol == 6 {
        // TCP
        if let Some(tcp) =
            unsafe { parser::ptr_at::<parser::TcpHdr>(ctx, parser::ETH_HDR_LEN + ip_hdr_len) }
        {
            tcp_hdr_len = (unsafe { (*tcp).doff() } as usize) * 4;

            if runtime.syn_proxy_enabled != 0 {
                // SYN Cookie 代理：对 SYN 回复 SYN-ACK，对合法 ACK 放行
                if let Some(action) = syn_cookie::handle_syn(ctx, ip, ip_hdr_len) {
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
                if let Some(action) = syn_cookie::handle_ack(ctx, ip, ip_hdr_len) {
                    unsafe {
                        if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                            (*stats).total_passed += 1;
                        }
                    }
                    return Ok(action);
                }
            } else {
                let tcp_flags = unsafe { (*tcp).flags() };
                if syn_flood::handle_syn_flood(ctx, saddr_host, tcp_flags, now_ns) {
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
    }

    // 6. L7 轻量指纹扫描（TCP 载荷前 64 字节）
    if protocol == 6 && tcp_hdr_len > 0 && l7_scan::scan(ctx, saddr_host, ip_hdr_len) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
                stats.l7_blocked += 1;
            }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // 7. 速率限制检查（触发则加入黑名单并 DROP）
    if rate_limit::check_rate_limit(saddr_host, now_ns) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
                stats.rate_limited += 1;
            }
        }
        rate_limit::emit_rate_limit_event(ctx, saddr_host, protocol);
        return Ok(xdp_action::XDP_DROP);
    }

    // 6. 黑名单检查
    if blacklist::is_blacklisted(saddr_host, now_ns) {
        unsafe {
            if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
                let stats = &mut *stats;
                stats.total_dropped += 1;
            }
        }
        blacklist::emit_blacklist_event(ctx, saddr_host, protocol);
        return Ok(xdp_action::XDP_DROP);
    }

    // 6. 默认放行
    unsafe {
        if let Some(stats) = GLOBAL_STATS.get_ptr_mut(0) {
            (*stats).total_passed += 1;
        }
    }
    Ok(xdp_action::XDP_PASS)
}

fn is_whitelisted(saddr: u32) -> bool {
    // 精确匹配 /32
    let key = LpmKey::new(32, WhitelistKey { addr: saddr });
    if WHITELIST.get(&key).is_some() {
        return true;
    }

    // TODO(phase1+): 支持任意 CIDR 前缀匹配
    false
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

use aya_ebpf::programs::XdpContext;

use crate::blacklist::add_to_blacklist;
use crate::maps::CONFIG;
use crate::rate_counter::{update_rate_counter, RateUpdate};
use eshield_common::{rules, IpKey};

/// 检测并处理 ICMP/ICMPv6 Flood：对单 IP 的 ICMP Echo Request 做速率限制，超限即 DROP 并加黑名单。
pub fn handle_icmp_flood(_ctx: &XdpContext, src: &IpKey, now_ns: u64, _protocol: u8) -> bool {
    let runtime = match CONFIG.get(0) {
        Some(c) => c,
        None => return false,
    };

    if runtime.icmp_flood_enabled == 0 {
        return false;
    }

    let mut update = RateUpdate {
        counter: 0,
        threshold: 0,
        block_duration_s: 0,
    };
    if !update_rate_counter(src, now_ns, &mut update) {
        return false;
    }

    if update.counter > update.threshold {
        add_to_blacklist(
            src,
            now_ns,
            update.block_duration_s,
            rules::ICMP_FLOOD as u8,
        );
        return true;
    }

    false
}

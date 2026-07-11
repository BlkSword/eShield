use aya_ebpf::programs::XdpContext;

use crate::blacklist::add_to_blacklist;
use crate::maps::CONFIG;
use crate::rate_counter::update_rate_counter;
use eshield_common::{rules, IpKey};

/// 检测并处理 UDP Flood：对单 IP 的 UDP 包做速率限制，超限即 DROP 并加黑名单。
pub fn handle_udp_flood(_ctx: &XdpContext, src: &IpKey, now_ns: u64) -> bool {
    let runtime = match CONFIG.get(0) {
        Some(c) => *c,
        None => return false,
    };

    if runtime.udp_flood_enabled == 0 {
        return false;
    }

    let Some(update) = update_rate_counter(src, now_ns) else {
        return false;
    };

    if update.counter > update.cfg.threshold {
        add_to_blacklist(
            src,
            now_ns,
            update.cfg.block_duration_s,
            rules::UDP_FLOOD as u8,
        );
        return true;
    }

    false
}

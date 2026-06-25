use aya_ebpf::programs::XdpContext;

use crate::maps::{BLACKLIST, CONFIG, EVENTS, RATE_LIMIT_CFG, RATE_MAP};
use eshield_common::{rules, BlockEntry, DropEvent, IpKey, RateCounter, RateLimitConfig};

/// 检测并处理 UDP Flood：对单 IP 的 UDP 包做速率限制，超限即 DROP 并加黑名单。
pub fn handle_udp_flood(ctx: &XdpContext, src: &IpKey, now_ns: u64) -> bool {
    let runtime = match CONFIG.get(0) {
        Some(c) => *c,
        None => return false,
    };

    if runtime.udp_flood_enabled == 0 {
        return false;
    }

    let cfg = match RATE_LIMIT_CFG.get(0) {
        Some(c) => *c,
        None => RateLimitConfig::default(),
    };

    let tick_ns = if cfg.tick_ms > u64::MAX / 1_000_000 {
        u64::MAX
    } else {
        cfg.tick_ms * 1_000_000
    };
    if tick_ns == 0 {
        return false;
    }

    let mut counter: u64 = 1;
    let mut last_decay_ns: u64 = now_ns;

    if let Some(entry) = unsafe { RATE_MAP.get(src) } {
        let elapsed_ns = now_ns.saturating_sub(entry.last_decay_ns);
        let ticks = elapsed_ns / tick_ns;
        let effective_ticks = ticks.min(64);

        let mut decayed = entry.counter;
        for _ in 0..effective_ticks {
            decayed = (decayed * cfg.decay_num) / cfg.decay_den;
        }

        counter = decayed.saturating_add(1);
        last_decay_ns = now_ns;
    }

    let updated = RateCounter {
        counter,
        last_decay_ns,
        padding: [0; 16],
    };
    let _ = RATE_MAP.insert(src, &updated, 0);

    if counter > cfg.threshold {
        add_to_blacklist(src, now_ns, cfg.block_duration_s);
        emit_udp_flood_event(ctx, src);
        return true;
    }

    false
}

fn add_to_blacklist(src: &IpKey, now_ns: u64, block_duration_s: u64) {
    let blocked_until_ns = if block_duration_s == 0 {
        0
    } else {
        let block_ns = if block_duration_s > u64::MAX / 1_000_000_000 {
            u64::MAX
        } else {
            block_duration_s * 1_000_000_000
        };
        now_ns.saturating_add(block_ns)
    };

    let entry = BlockEntry {
        blocked_until_ns,
        block_reason: rules::UDP_FLOOD as u8,
        hit_count: 0,
        first_seen_ns: now_ns,
    };

    let _ = BLACKLIST.insert(src, &entry, 0);
}

pub fn emit_udp_flood_event(_ctx: &XdpContext, src: &IpKey) {
    unsafe {
        if let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) {
            let event = DropEvent {
                timestamp_ns: aya_ebpf::helpers::gen::bpf_ktime_get_ns(),
                src_ip: src.addr,
                family: src.family,
                protocol: 17, // UDP
                rule_id: rules::UDP_FLOOD,
                padding: [0; 4],
            };
            entry.write(event);
            entry.submit(0);
        }
    }
}

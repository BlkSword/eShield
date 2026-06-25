use aya_ebpf::programs::XdpContext;

use crate::maps::{BLACKLIST, CONFIG, EVENTS, RATE_LIMIT_CFG, RATE_MAP};
use eshield_common::{rules, BlockEntry, DropEvent, IpKey, RateCounter, RateLimitConfig};

/// 检查并更新 src 的速率计数器；若超限则加入黑名单并返回 true。
pub fn check_rate_limit(src: &IpKey, now_ns: u64) -> bool {
    let cfg = match RATE_LIMIT_CFG.get(0) {
        Some(c) => *c,
        None => RateLimitConfig::default(),
    };

    let runtime = match CONFIG.get(0) {
        Some(c) => *c,
        None => return false,
    };

    if runtime.rate_limit_enabled == 0 {
        return false;
    }

    // 避免 saturating_mul 在 u64 上生成 __multi3 软浮点调用
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

    match unsafe { RATE_MAP.get(src) } {
        Some(entry) => {
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
        None => {
            // 新 IP，counter 保持 1
        }
    }

    let updated = RateCounter {
        counter,
        last_decay_ns,
        padding: [0; 16],
    };
    let _ = RATE_MAP.insert(src, &updated, 0);

    if counter > cfg.threshold {
        add_to_blacklist(src, now_ns, cfg.block_duration_s);
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
        block_reason: rules::RATE_LIMIT as u8,
        hit_count: 0,
        first_seen_ns: now_ns,
    };

    let _ = BLACKLIST.insert(src, &entry, 0);
}

pub fn emit_rate_limit_event(_ctx: &XdpContext, src: &IpKey, protocol: u8) {
    unsafe {
        if let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) {
            let event = DropEvent {
                timestamp_ns: aya_ebpf::helpers::gen::bpf_ktime_get_ns(),
                src_ip: src.addr,
                family: src.family,
                protocol,
                rule_id: rules::RATE_LIMIT,
                padding: [0; 4],
            };
            entry.write(event);
            entry.submit(0);
        }
    }
}

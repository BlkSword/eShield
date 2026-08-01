use crate::blacklist::add_to_blacklist;
use crate::maps::CONFIG;
use crate::rate_counter::{update_rate_counter, RateUpdate};
use eshield_common::{rules, IpKey};

/// 检查并更新 src 的速率计数器；若超限则加入黑名单并返回 true。
/// 独立栈帧（BPF 512 字节组合栈限制）。
#[inline(never)]

pub fn check_rate_limit(src: &IpKey, now_ns: u64) -> bool {
    let runtime = match CONFIG.get(0) {
        Some(c) => c,
        None => return false,
    };

    if runtime.rate_limit_enabled == 0 {
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
            rules::RATE_LIMIT as u8,
        );
        return true;
    }

    false
}

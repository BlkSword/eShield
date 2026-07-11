use crate::blacklist::add_to_blacklist;
use crate::maps::CONFIG;
use crate::rate_counter::update_rate_counter;
use eshield_common::{rules, IpKey};

/// 检查并更新 src 的速率计数器；若超限则加入黑名单并返回 true。
pub fn check_rate_limit(src: &IpKey, now_ns: u64) -> bool {
    let runtime = match CONFIG.get(0) {
        Some(c) => *c,
        None => return false,
    };

    if runtime.rate_limit_enabled == 0 {
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
            rules::RATE_LIMIT as u8,
        );
        return true;
    }

    false
}

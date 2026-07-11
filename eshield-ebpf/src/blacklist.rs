use crate::maps::BLACKLIST;
use eshield_common::{BlockEntry, IpKey, BLOCK_PERMANENT};

pub fn is_blacklisted(src: &IpKey, now_ns: u64) -> bool {
    match unsafe { BLACKLIST.get(src) } {
        Some(entry) => {
            // BLOCK_PERMANENT 表示永久封禁
            if entry.blocked_until_ns == BLOCK_PERMANENT || entry.blocked_until_ns > now_ns {
                // 命中黑名单时递增 hit_count，供用户态 top_attackers 使用
                let mut updated = *entry;
                updated.hit_count = updated.hit_count.saturating_add(1);
                let _ = BLACKLIST.insert(src, &updated, 0);
                return true;
            }
        }
        None => return false,
    }

    // 已过期，从黑名单中移除
    let _ = BLACKLIST.remove(src);
    false
}

/// 将源 IP 加入黑名单。`block_duration_s == 0` 表示永久封禁。
pub fn add_to_blacklist(src: &IpKey, now_ns: u64, block_duration_s: u64, reason: u8) {
    let blocked_until_ns = if block_duration_s == 0 {
        BLOCK_PERMANENT
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
        block_reason: reason,
        hit_count: 0,
        first_seen_ns: now_ns,
    };

    let _ = BLACKLIST.insert(src, &entry, 0);
}

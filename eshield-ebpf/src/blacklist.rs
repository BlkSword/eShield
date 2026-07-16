use crate::maps::{BLACKLIST, TRUST_MAP};
use eshield_common::{BlockEntry, IpKey, TrustEntry, BLOCK_PERMANENT, TRUST_DEFAULT, TRUST_MIN};

pub fn is_blacklisted(src: &IpKey, now_ns: u64) -> bool {
    match unsafe { BLACKLIST.get(src) } {
        Some(entry) => {
            // BLOCK_PERMANENT 表示永久封禁
            if entry.blocked_until_ns == BLOCK_PERMANENT || entry.blocked_until_ns > now_ns {
                // 命中黑名单时递增 hit_count，供持久化/审计使用。
                // Top 攻击源由主流程 drop_packet 统一维护，避免重复计数。
                let mut updated = *entry;
                updated.hit_count = updated.hit_count.saturating_add(1);
                let _ = BLACKLIST.insert(src, &updated, 0);
                return true;
            }
        }
        None => return false,
    }

    // 已过期，从黑名单中移除；同时将 Trust Score 重置为默认中性值
    let _ = BLACKLIST.remove(src);
    reset_trust(src);
    false
}

/// 将源 IP 加入黑名单。同时将 Trust Score 强制归零，
/// 防止攻击者先积累信任再发起攻击的「信誉洗白」行为。
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

    // Trust Score 归零：一旦被判定为攻击源，之前积累的信任全部作废
    let trust_entry = TrustEntry {
        trust_score: TRUST_MIN,
        last_update_ns: now_ns,
        ..TrustEntry::default()
    };
    let _ = TRUST_MAP.insert(src, &trust_entry, 0);
}

/// 黑名单过期后，将 Trust Score 重置回默认中性值（给予重新观察的机会）。
#[inline(always)]
fn reset_trust(src: &IpKey) {
    let entry = TrustEntry {
        trust_score: TRUST_DEFAULT,
        ..TrustEntry::default()
    };
    let _ = TRUST_MAP.insert(src, &entry, 0);
}

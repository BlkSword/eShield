use eshield_common::IpKey;

use crate::maps::CHALLENGE_ALLOWLIST;

/// 检查源 IP 是否已通过 Challenge 验证且未过期。
pub fn is_allowed(src: &IpKey, now_ns: u64) -> bool {
    match unsafe { CHALLENGE_ALLOWLIST.get(src) } {
        Some(expiry) if *expiry > now_ns => true,
        _ => false,
    }
}

/// 从 eBPF 侧删除已过期或需要回收的条目（可选，LRU map 会自动回收）。
#[allow(dead_code)]
pub fn remove(src: &IpKey) {
    let _ = CHALLENGE_ALLOWLIST.remove(src);
}

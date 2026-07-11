//! Trust Score (v0.4.0) — IP 双向信誉引擎。
//!
//! - `trust_pass`：PASS 事件缓慢加分，`trust += (1000 - trust) / 100`
//! - `trust_drop`：DROP 事件快速减分，`trust -= trust / 3`
//! - `trust_factor`：返回速率阈值调制因子（定点放大 1000 倍）

use crate::maps::TRUST_MAP;
use eshield_common::{
    IpKey, TrustEntry, TRUST_ADD_DIVISOR, TRUST_DEFAULT, TRUST_MAX, TRUST_MIN, TRUST_SUB_DIVISOR,
};

/// PASS 事件：缓慢增加信任分。
#[inline(always)]
pub fn trust_pass(src: &IpKey, now_ns: u64) {
    let mut entry = match unsafe { TRUST_MAP.get(src) } {
        Some(e) => *e,
        None => TrustEntry {
            trust_score: TRUST_DEFAULT,
            ..TrustEntry::default()
        },
    };
    entry.pass_count = entry.pass_count.saturating_add(1);
    let delta = TRUST_MAX.saturating_sub(entry.trust_score) / TRUST_ADD_DIVISOR;
    entry.trust_score = (entry.trust_score + delta).min(TRUST_MAX);
    entry.last_update_ns = now_ns;
    entry.level = trust_level(entry.trust_score);
    let _ = TRUST_MAP.insert(src, &entry, 0);
}

/// DROP 事件：快速降低信任分。
#[inline(always)]
pub fn trust_drop(src: &IpKey, now_ns: u64) {
    let mut entry = match unsafe { TRUST_MAP.get(src) } {
        Some(e) => *e,
        None => TrustEntry {
            trust_score: TRUST_DEFAULT,
            ..TrustEntry::default()
        },
    };
    entry.drop_count = entry.drop_count.saturating_add(1);
    entry.trust_score = entry.trust_score.saturating_sub(entry.trust_score / TRUST_SUB_DIVISOR);
    entry.trust_score = entry.trust_score.max(TRUST_MIN);
    entry.last_update_ns = now_ns;
    entry.level = trust_level(entry.trust_score);
    let _ = TRUST_MAP.insert(src, &entry, 0);
}

/// 读取 src 的信誉因子（定点放大 1000 倍，用于调制速率阈值）。
///
/// 公式：`factor = (500 + trust_score) × 1000 / 1500`
/// - trust=1000 → factor=1000（阈值不变）
/// - trust=500  → factor=667（阈值收紧 33%）
/// - trust=0    → factor=333（阈值收紧 67%）
#[inline(always)]
pub fn trust_factor(src: &IpKey) -> u64 {
    let trust = match unsafe { TRUST_MAP.get(src) } {
        Some(e) => e.trust_score as u64,
        None => TRUST_DEFAULT as u64,
    };
    (500u64 + trust).saturating_mul(1000) / 1500
}

/// 合并全局危险等级的最终阈值调制因子。
/// danger_level: 0=normal(×1.0), 1=elevated(×0.75), 2=critical(×0.5)
#[inline(always)]
pub fn danger_factor(danger_level: u8) -> u64 {
    match danger_level {
        2 => 500,
        1 => 750,
        _ => 1000,
    }
}

#[inline(always)]
fn trust_level(score: u32) -> u8 {
    if score >= 700 {
        1 // trusted
    } else if score >= 300 {
        2 // neutral
    } else if score >= 100 {
        3 // suspicious
    } else {
        4 // malicious
    }
}

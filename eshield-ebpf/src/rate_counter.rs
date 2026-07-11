use crate::maps::{CONFIG, RATE_LIMIT_CFG, RATE_MAP};
use crate::trust;
use eshield_common::pure::decay_counter;
use eshield_common::{IpKey, RateCounter, RateLimitConfig};

/// 更新 `RATE_MAP` 中 src 的指数衰减速率计数器，并返回当前计数与调制后的阈值。
/// 如果 `tick_ms` 为 0 或无法读取配置，则返回 `None`。
///
/// `effective_threshold` 会结合 Trust Score 与 Danger Level 动态调制。
pub fn update_rate_counter(src: &IpKey, now_ns: u64) -> Option<RateUpdate> {
    let cfg = RATE_LIMIT_CFG.get(0)?;

    // 避免 saturating_mul 在 u64 上生成 __multi3 软浮点调用
    let tick_ns = if cfg.tick_ms > u64::MAX / 1_000_000 {
        u64::MAX
    } else {
        cfg.tick_ms * 1_000_000
    };
    if tick_ns == 0 {
        return None;
    }

    let mut counter: u64 = 1;
    let mut last_decay_ns: u64 = now_ns;

    if let Some(entry) = unsafe { RATE_MAP.get(src) } {
        let elapsed_ns = now_ns.saturating_sub(entry.last_decay_ns);
        let decayed = decay_counter(entry.counter, elapsed_ns, tick_ns, cfg.decay_num, cfg.decay_den);

        counter = decayed.saturating_add(1);
        last_decay_ns = now_ns;
    }

    let updated = RateCounter {
        counter,
        last_decay_ns,
        padding: [0; 16],
    };
    let _ = RATE_MAP.insert(src, &updated, 0);

    // 动态阈值调制（v0.4.0）：结合 Trust Score 与 Danger Level
    // 分步乘除避免 u64 溢出产生 __multi3 调用
    let runtime = CONFIG.get(0)?;
    let effective_threshold = if runtime.trust_enabled != 0 {
        let trust_f = trust::trust_factor(src);       // 范围 333..=1000
        let danger_f = trust::danger_factor(runtime.danger_level); // 500/750/1000
        modulate_threshold(cfg.threshold, trust_f, danger_f)
    } else {
        cfg.threshold
    };

    Some(RateUpdate {
        counter,
        threshold: effective_threshold,
        cfg: *cfg,
    })
}

/// 计算 `base × trust_f / 1000 × danger_f / 1000`。
/// trust_f 和 danger_f 都是有界小整数（≤1000），因此分步乘除可避免 `__multi3`。
#[inline(always)]
fn modulate_threshold(base: u64, trust_f: u64, danger_f: u64) -> u64 {
    // u64::MAX ≈ 1.84e19；base × 1000 ≤ u64::MAX 时不会溢出
    // SAFE_BASE_MAX = u64::MAX / 1000（编译期常量，无 __multi3）
    const SAFE_MAX: u64 = u64::MAX / 1000;
    let step1 = if base > SAFE_MAX {
        base / 1000 * trust_f
    } else {
        base * trust_f / 1000
    };
    if step1 > SAFE_MAX {
        step1 / 1000 * danger_f
    } else {
        step1 * danger_f / 1000
    }
}

pub struct RateUpdate {
    pub counter: u64,
    /// 经过 Trust Score + Danger Level 调制后的有效阈值（v0.4.0）
    pub threshold: u64,
    pub cfg: RateLimitConfig,
}

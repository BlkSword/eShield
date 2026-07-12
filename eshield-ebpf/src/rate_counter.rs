use crate::maps::{CONFIG, RATE_LIMIT_CFG, RATE_MAP};
use crate::trust;
use eshield_common::pure::decay_counter;
use eshield_common::{IpKey, RateCounter};

/// 速率更新结果。调用者在栈上分配并通过 `&mut` 传入，避免 eBPF 中返回聚合类型。
pub struct RateUpdate {
    pub counter: u64,
    /// 经过 Trust Score + Danger Level 调制后的有效阈值
    pub threshold: u64,
    /// 触发限流时加入黑名单的封禁时长（秒）
    pub block_duration_s: u64,
}

/// 更新 `RATE_MAP` 中 src 的指数衰减速率计数器，并把结果写入 `out`。
/// 返回 `true` 表示成功更新；`tick_ns` 为 0 或无法读取配置时返回 `false`。
///
/// `out.threshold` 会结合 Trust Score 与 Danger Level 动态调制。
pub fn update_rate_counter(src: &IpKey, now_ns: u64, out: &mut RateUpdate) -> bool {
    let cfg = match RATE_LIMIT_CFG.get(0) {
        Some(c) => c,
        None => return false,
    };

    // 避免 tick_ms * 1_000_000 被编译器 widening 到 128 位产生 __multi3
    let tick_ns = if cfg.tick_ms > u64::MAX / 1_000_000 {
        u64::MAX
    } else {
        cfg.tick_ms.wrapping_mul(1_000_000)
    };
    if tick_ns == 0 {
        return false;
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
    let runtime = match CONFIG.get(0) {
        Some(r) => r,
        None => return false,
    };
    let effective_threshold = if runtime.trust_enabled != 0 {
        let trust_f = trust::trust_factor(src); // 范围 333..=1000
        let danger_f = trust::danger_factor(runtime.danger_level); // 500/750/1000
        modulate_threshold(cfg.threshold, trust_f, danger_f)
    } else {
        cfg.threshold
    };

    out.counter = counter;
    out.threshold = effective_threshold;
    out.block_duration_s = cfg.block_duration_s;
    true
}

/// 计算 `base × trust_f / 1000 × danger_f / 1000`。
/// trust_f 和 danger_f 都是有界小整数（≤1000），分步乘除并使用 wrapping_mul
/// 避免编译器生成 128 位中间值调用 __multi3。
#[inline(always)]
fn modulate_threshold(base: u64, trust_f: u64, danger_f: u64) -> u64 {
    const SAFE_MAX: u64 = u64::MAX / 1000;
    let step1 = if base > SAFE_MAX {
        base.wrapping_div(1000).wrapping_mul(trust_f)
    } else {
        base.wrapping_mul(trust_f).wrapping_div(1000)
    };
    if step1 > SAFE_MAX {
        step1.wrapping_div(1000).wrapping_mul(danger_f)
    } else {
        step1.wrapping_mul(danger_f).wrapping_div(1000)
    }
}

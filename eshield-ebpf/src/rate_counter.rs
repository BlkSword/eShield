use crate::maps::{RATE_LIMIT_CFG, RATE_MAP};
use eshield_common::pure::decay_counter;
use eshield_common::{IpKey, RateCounter, RateLimitConfig};

/// 更新 `RATE_MAP` 中 src 的指数衰减速率计数器，并返回当前计数与配置。
/// 如果 `tick_ms` 为 0 或无法读取配置，则返回 `None`。
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
    Some(RateUpdate { counter, cfg: *cfg })
}

pub struct RateUpdate {
    pub counter: u64,
    pub cfg: RateLimitConfig,
}

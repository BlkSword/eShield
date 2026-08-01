use crate::maps::{PORT_RATE_LIMIT_CFG, PORT_RATE_MAP};
use eshield_common::{PortRateKey, RateCounter};

/// 按目的端口速率计数并返回是否超限。
///
/// 防换源 IP 绕过：per-IP 限速在源 IP 随机化时失效，
/// 按（协议 + 目的端口）计数后，无论源 IP 如何变化，打在同一个
/// 端口上的流量都会累计并触发 DROP。
///
/// 计数语义为**固定滑动窗口**（每 `tick_ms` 重置）：窗口内包数 > 阈值即超限。
/// 不使用指数衰减——包间隔 < 1 tick 时整数衰减（elapsed/tick == 0）会失效，
/// counter 单调增长且无法恢复，低速率流量（如 90pps 打同一端口）也会被误伤。
/// 固定窗口在攻击停止后下一个 tick 即恢复放行。
///
/// 超限仅 DROP，不加入黑名单（攻击源随机化时黑名单无意义）。
/// 独立栈帧（BPF 512 字节组合栈限制）。
#[inline(never)]
pub fn check_port_rate(key: &PortRateKey, now_ns: u64) -> bool {
    let cfg = match PORT_RATE_LIMIT_CFG.get(0) {
        Some(c) => *c,
        None => return false,
    };

    // 避免 tick_ms * 1_000_000 被编译器 widening 到 128 位产生 __multi3
    let window_ns = if cfg.tick_ms > u64::MAX / 1_000_000 {
        u64::MAX
    } else {
        cfg.tick_ms.wrapping_mul(1_000_000)
    };
    if window_ns == 0 {
        return false;
    }

    let mut count: u64 = 1;
    let mut window_start: u64 = now_ns;

    if let Some(entry) = unsafe { PORT_RATE_MAP.get(key) } {
        // 仍在同一窗口内：继续累计；否则开启新窗口
        if now_ns.saturating_sub(entry.last_decay_ns) < window_ns {
            count = entry.counter.saturating_add(1);
            window_start = entry.last_decay_ns;
        }
    }

    let updated = RateCounter {
        counter: count,
        last_decay_ns: window_start,
        padding: [0; 16],
    };
    let _ = PORT_RATE_MAP.insert(key, &updated, 0);

    count > cfg.threshold
}

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

const NS_PER_S: u64 = 1_000_000_000;

pub struct RateLimiter {
    buckets: DashMap<String, (AtomicU64, AtomicU64)>,
    rate_per_s: u64,
    burst: u64,
}

impl RateLimiter {
    pub fn new(rate_per_s: u64, burst: u64) -> Self {
        Self {
            buckets: DashMap::new(),
            rate_per_s,
            burst,
        }
    }

    pub fn check(&self, node_name: &str, now_ns: u64) -> bool {
        let entry = self
            .buckets
            .entry(node_name.to_string())
            .or_insert_with(|| (AtomicU64::new(self.burst), AtomicU64::new(now_ns)));

        let (tokens, last) = entry.value();
        let last_ns = last.load(Ordering::Relaxed);
        let elapsed_ns = now_ns.saturating_sub(last_ns);
        if elapsed_ns > 0 {
            // 按纳秒精确回填，且只在真正回填时更新 last：
            // 旧实现每次请求都重置 last 且按整秒取模，请求间隔 <1s 时永远不补充 token。
            let added = ((elapsed_ns as u128 * self.rate_per_s as u128) / NS_PER_S as u128) as u64;
            if added > 0 {
                let current = tokens.load(Ordering::Relaxed);
                tokens.store(
                    current.saturating_add(added).min(self.burst),
                    Ordering::Relaxed,
                );
                last.store(now_ns, Ordering::Relaxed);
            }
        }

        tokens
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if current > 0 {
                    Some(current - 1)
                } else {
                    None
                }
            })
            .is_ok()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(100, 200)
    }
}

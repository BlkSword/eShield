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
        let elapsed_s = now_ns.saturating_sub(last_ns) / NS_PER_S;
        let added = elapsed_s.saturating_mul(self.rate_per_s);

        let current = tokens.load(Ordering::Relaxed);
        let new_tokens = (current.saturating_add(added)).min(self.burst);

        if new_tokens == 0 {
            last.store(now_ns, Ordering::Relaxed);
            return false;
        }

        tokens.store(new_tokens - 1, Ordering::Relaxed);
        last.store(now_ns, Ordering::Relaxed);
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(100, 200)
    }
}

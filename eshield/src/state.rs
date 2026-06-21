use dashmap::DashMap;
use eshield_common::rules;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Stats {
    #[allow(dead_code)]
    pub total_packets: AtomicU64,
    pub total_dropped: AtomicU64,
    #[allow(dead_code)]
    pub total_passed: AtomicU64,
    pub blacklist_blocked: AtomicU64,
    pub rate_limited: AtomicU64,
    pub syn_flood_blocked: AtomicU64,
    pub l7_blocked: AtomicU64,
    pub adaptive_blocked: AtomicU64,
    pub top_attackers: DashMap<u32, AtomicU64>,
}

impl Stats {
    /// 批量聚合上报：减少高并发 DROP 事件下的原子操作与 DashMap 竞争。
    pub fn add_dropped_batch(&self, by_reason: &HashMap<u16, u64>, by_source: &HashMap<u32, u64>) {
        if by_source.is_empty() {
            return;
        }

        let total: u64 = by_source.values().sum();
        self.total_dropped.fetch_add(total, Ordering::Relaxed);

        for (&reason, &count) in by_reason {
            let counter = match reason {
                r if r == rules::BLACKLIST => &self.blacklist_blocked,
                r if r == rules::RATE_LIMIT => &self.rate_limited,
                r if r == rules::SYN_FLOOD => &self.syn_flood_blocked,
                r if r == rules::L7_PATTERN => &self.l7_blocked,
                r if r == rules::ADAPTIVE => &self.adaptive_blocked,
                _ => &self.total_dropped,
            };
            counter.fetch_add(count, Ordering::Relaxed);
        }

        for (&src_ip, &count) in by_source {
            self.top_attackers
                .entry(src_ip)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(count, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppStateInner {
    pub stats: Arc<Stats>,
}

impl AppStateInner {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(Stats::default()),
        }
    }
}

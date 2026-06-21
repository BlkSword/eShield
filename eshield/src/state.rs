use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Stats {
    #[allow(dead_code)]
    pub total_packets: AtomicU64,
    pub total_dropped: AtomicU64,
    #[allow(dead_code)]
    pub total_passed: AtomicU64,
    pub top_attackers: DashMap<u32, AtomicU64>,
}

impl Stats {
    pub fn add_dropped(&self, src_ip: u32) {
        self.total_dropped.fetch_add(1, Ordering::Relaxed);
        self.top_attackers
            .entry(src_ip)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
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

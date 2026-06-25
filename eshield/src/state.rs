use dashmap::DashMap;
use eshield_common::{rules, IpKey};
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
    pub udp_flood_blocked: AtomicU64,
    pub icmp_flood_blocked: AtomicU64,
    pub top_attackers: DashMap<IpKey, AtomicU64>,
}

impl Stats {
    /// 批量聚合上报：减少高并发 DROP 事件下的原子操作与 DashMap 竞争。
    pub fn add_dropped_batch(
        &self,
        by_reason: &HashMap<u16, u64>,
        by_source: &HashMap<IpKey, u64>,
    ) {
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
                r if r == rules::PORT_ACL => &self.total_dropped,
                r if r == rules::UDP_FLOOD => &self.udp_flood_blocked,
                r if r == rules::ICMP_FLOOD => &self.icmp_flood_blocked,
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

#[cfg(test)]
mod tests {
    use super::*;
    use eshield_common::IpFamily;
    use std::collections::HashMap;

    #[test]
    fn test_add_dropped_batch_aggregates_totals() {
        let stats = Stats::default();
        let mut by_reason = HashMap::new();
        by_reason.insert(rules::BLACKLIST, 3);
        by_reason.insert(rules::RATE_LIMIT, 2);
        let mut by_source = HashMap::new();
        by_source.insert(IpKey::from_ipv4([192, 0, 2, 1]), 5);

        stats.add_dropped_batch(&by_reason, &by_source);

        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 5);
        assert_eq!(stats.blacklist_blocked.load(Ordering::Relaxed), 3);
        assert_eq!(stats.rate_limited.load(Ordering::Relaxed), 2);
        assert_eq!(
            stats
                .top_attackers
                .get(&IpKey::from_ipv4([192, 0, 2, 1]))
                .unwrap()
                .load(Ordering::Relaxed),
            5
        );
    }

    #[test]
    fn test_add_dropped_batch_empty_is_noop() {
        let stats = Stats::default();
        stats.add_dropped_batch(&HashMap::new(), &HashMap::new());
        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 0);
        assert!(stats.top_attackers.is_empty());
    }

    #[test]
    fn test_add_dropped_batch_unknown_reason_ignored() {
        let stats = Stats::default();
        let mut by_reason = HashMap::new();
        by_reason.insert(0xFFFF, 7);
        let mut by_source = HashMap::new();
        by_source.insert(IpKey::from_ipv4([10, 0, 0, 1]), 7);

        stats.add_dropped_batch(&by_reason, &by_source);

        assert_eq!(stats.total_dropped.load(Ordering::Relaxed), 7);
        assert_eq!(stats.blacklist_blocked.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rate_limited.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_add_dropped_batch_udp_icmp_flood() {
        let stats = Stats::default();
        let mut by_reason = HashMap::new();
        by_reason.insert(rules::UDP_FLOOD, 4);
        by_reason.insert(rules::ICMP_FLOOD, 3);
        let mut by_source = HashMap::new();
        by_source.insert(IpKey::from_ipv6([0; 16]), 7);

        stats.add_dropped_batch(&by_reason, &by_source);

        assert_eq!(stats.udp_flood_blocked.load(Ordering::Relaxed), 4);
        assert_eq!(stats.icmp_flood_blocked.load(Ordering::Relaxed), 3);
        assert_eq!(
            stats
                .top_attackers
                .get(&IpKey::from_ipv6([0; 16]))
                .unwrap()
                .load(Ordering::Relaxed),
            7
        );
    }
}

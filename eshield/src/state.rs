use dashmap::DashMap;
use eshield_common::{rules, DropEvent, IpKey};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

use crate::timeseries::TimeSeriesWindow;

#[derive(Debug)]
pub struct Stats {
    pub total_packets: AtomicU64,
    pub total_dropped: AtomicU64,
    pub total_passed: AtomicU64,
    pub blacklist_blocked: AtomicU64,
    pub rate_limited: AtomicU64,
    pub syn_flood_blocked: AtomicU64,
    pub l7_blocked: AtomicU64,
    pub adaptive_blocked: AtomicU64,
    pub udp_flood_blocked: AtomicU64,
    pub icmp_flood_blocked: AtomicU64,
    pub geoip_blocked: AtomicU64,
    pub tcp_rst_sent: AtomicU64,
    pub tcp_rst_fail: AtomicU64,
    pub tcp_rst_attempt: AtomicU64,
    pub current_pps: AtomicU64,
    pub current_dps: AtomicU64,
    pub tcp_dropped: AtomicU64,
    pub udp_dropped: AtomicU64,
    pub icmp_dropped: AtomicU64,
    pub other_dropped: AtomicU64,
    /// 程序启动时的 CLOCK_MONOTONIC 时间（ns），用于过滤 Ring Buffer 中的 stale 事件。
    pub program_start_ns: AtomicU64,
    pub port_dropped: DashMap<u16, AtomicU64>,
    pub process_hist: [AtomicU64; 6],
    pub top_attackers: DashMap<IpKey, AtomicU64>,
    /// Trust Score 信誉分布（v0.4.0）
    pub trust_trusted: AtomicU64,
    pub trust_neutral: AtomicU64,
    pub trust_suspicious: AtomicU64,
    pub trust_malicious: AtomicU64,
    /// 全局危险等级 0/1/2（v0.4.0）
    pub danger_level: AtomicU64,
    /// 最近攻击事件环形缓冲（最多 1000 条）
    pub recent_attacks: Mutex<VecDeque<DropEvent>>,
    pub timeseries: Arc<RwLock<TimeSeriesWindow>>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_passed: AtomicU64::new(0),
            blacklist_blocked: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            syn_flood_blocked: AtomicU64::new(0),
            l7_blocked: AtomicU64::new(0),
            adaptive_blocked: AtomicU64::new(0),
            udp_flood_blocked: AtomicU64::new(0),
            icmp_flood_blocked: AtomicU64::new(0),
            geoip_blocked: AtomicU64::new(0),
            tcp_rst_sent: AtomicU64::new(0),
            tcp_rst_fail: AtomicU64::new(0),
            tcp_rst_attempt: AtomicU64::new(0),
            current_pps: AtomicU64::new(0),
            current_dps: AtomicU64::new(0),
            tcp_dropped: AtomicU64::new(0),
            udp_dropped: AtomicU64::new(0),
            icmp_dropped: AtomicU64::new(0),
            other_dropped: AtomicU64::new(0),
            program_start_ns: AtomicU64::new(0),
            port_dropped: DashMap::new(),
            process_hist: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            top_attackers: DashMap::new(),
            trust_trusted: AtomicU64::new(0),
            trust_neutral: AtomicU64::new(0),
            trust_suspicious: AtomicU64::new(0),
            trust_malicious: AtomicU64::new(0),
            danger_level: AtomicU64::new(0),
            recent_attacks: Mutex::new(VecDeque::new()),
            timeseries: Arc::new(RwLock::new(TimeSeriesWindow::new(8640, 10))),
        }
    }
}

impl Stats {
    /// 批量聚合上报：减少高并发 DROP 事件下的原子操作与 DashMap 竞争。
    pub fn add_dropped_batch(
        &self,
        by_reason: &HashMap<u16, u64>,
        by_source: &HashMap<IpKey, u64>,
        by_port: &HashMap<u16, u64>,
    ) {
        if by_source.is_empty() {
            return;
        }

        // 总包数/总丢包数以及 SYN/UDP/ICMP/L7/GeoIP 等分类计数
        // 从 eBPF GLOBAL_STATS 同步；事件侧只更新没有独立全局计数器的
        // 黑名单、速率限制、自适应以及协议/端口/来源维度。
        for (&reason, &count) in by_reason {
            match reason {
                r if r == rules::BLACKLIST => self.blacklist_blocked.fetch_add(count, Ordering::Relaxed),
                r if r == rules::RATE_LIMIT => self.rate_limited.fetch_add(count, Ordering::Relaxed),
                r if r == rules::ADAPTIVE => self.adaptive_blocked.fetch_add(count, Ordering::Relaxed),
                _ => continue,
            };
        }

        for (&src_ip, &count) in by_source {
            self.top_attackers
                .entry(src_ip)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(count, Ordering::Relaxed);
        }

        for (&port, &count) in by_port {
            if port == 0 {
                continue;
            }
            self.port_dropped
                .entry(port)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(count, Ordering::Relaxed);
        }
    }

    /// 记录事件消费处理耗时（微秒）到直方图桶。
    pub fn record_process_time_us(&self, us: u64) {
        let idx = match us {
            0..=1000 => 0,
            1001..=5000 => 1,
            5001..=10000 => 2,
            10001..=50000 => 3,
            50001..=100000 => 4,
            _ => 5,
        };
        self.process_hist[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// 追加一条攻击事件到环形缓冲（最多保留 1000 条）。
    pub fn push_attack_event(&self, event: DropEvent) {
        let mut buf = self.recent_attacks.lock().unwrap();
        if buf.len() >= 1000 {
            buf.pop_front();
        }
        buf.push_back(event);
    }

    /// 返回最近的攻击事件快照。
    pub fn attack_events(&self, limit: usize) -> Vec<DropEvent> {
        let buf = self.recent_attacks.lock().unwrap();
        buf.iter().rev().take(limit).copied().collect()
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
    use std::collections::HashMap;

    #[test]
    fn test_add_dropped_batch_aggregates_totals() {
        let stats = Stats::default();
        let mut by_reason = HashMap::new();
        by_reason.insert(rules::BLACKLIST, 3);
        by_reason.insert(rules::RATE_LIMIT, 2);
        let mut by_source = HashMap::new();
        by_source.insert(IpKey::from_ipv4([192, 0, 2, 1]), 5);

        stats.add_dropped_batch(&by_reason, &by_source, &HashMap::new());

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
        stats.add_dropped_batch(&HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(stats.top_attackers.is_empty());
    }

    #[test]
    fn test_add_dropped_batch_unknown_reason_ignored() {
        let stats = Stats::default();
        let mut by_reason = HashMap::new();
        by_reason.insert(0xFFFF, 7);
        let mut by_source = HashMap::new();
        by_source.insert(IpKey::from_ipv4([10, 0, 0, 1]), 7);

        stats.add_dropped_batch(&by_reason, &by_source, &HashMap::new());

        assert_eq!(stats.blacklist_blocked.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rate_limited.load(Ordering::Relaxed), 0);
    }

}

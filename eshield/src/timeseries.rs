use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ip::format_ip_key;
use crate::state::Stats;

/// A single sampled metrics point.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MetricPoint {
    pub timestamp: u64,
    pub total_packets: u64,
    pub total_passed: u64,
    pub total_dropped: u64,
    pub blacklist_blocked: u64,
    pub rate_limited: u64,
    pub syn_flood_blocked: u64,
    pub l7_blocked: u64,
    pub adaptive_blocked: u64,
    pub udp_flood_blocked: u64,
    pub icmp_flood_blocked: u64,
    pub waf_blocked: u64,
    pub geoip_blocked: u64,
    pub challenge_issued: u64,
    /// Derived: dropped packets per second since the previous point.
    pub dps: u64,
    /// Derived: passed packets per second since the previous point.
    pub pps: u64,
    /// Snapshot of top attackers at this point: ip -> count.
    pub top_attackers: std::collections::HashMap<String, u64>,
}

/// Fixed-size in-memory ring buffer for time-series metrics.
///
/// Designed to be cheap enough to sample every few seconds from a tokio task
/// without introducing external TSDB dependencies for a single-node tool.
#[derive(Debug)]
pub struct TimeSeriesWindow {
    slots: Vec<MetricPoint>,
    capacity: usize,
    interval_s: u64,
    /// Timestamp of the most recently written slot (0 if none).
    head_timestamp: u64,
    /// Counters at the time of the most recent write, used to derive PPS/DPS.
    last_total_packets: u64,
    last_total_dropped: u64,
    last_total_passed: u64,
}

impl TimeSeriesWindow {
    /// Create a new window.
    ///
    /// `capacity` is the maximum number of slots retained.
    /// `interval_s` is the expected sampling interval; it is only used to
    /// filter snapshots by duration.
    pub fn new(capacity: usize, interval_s: u64) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            capacity,
            interval_s,
            head_timestamp: 0,
            last_total_packets: 0,
            last_total_dropped: 0,
            last_total_passed: 0,
        }
    }

    /// Record a new point from the current `Stats` snapshot.
    pub fn record(&mut self, stats: &Stats) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Avoid duplicate points within the same second.
        if now == self.head_timestamp && !self.slots.is_empty() {
            return;
        }

        let total_packets = stats.total_packets.load(Ordering::Relaxed);
        let total_dropped = stats.total_dropped.load(Ordering::Relaxed);
        let total_passed = stats.total_passed.load(Ordering::Relaxed);

        let elapsed = if self.head_timestamp == 0 {
            self.interval_s
        } else {
            now.saturating_sub(self.head_timestamp).max(1)
        };

        let dps = if self.head_timestamp == 0 {
            0
        } else {
            total_dropped.saturating_sub(self.last_total_dropped) / elapsed
        };
        let pps = if self.head_timestamp == 0 {
            0
        } else {
            total_passed.saturating_sub(self.last_total_passed) / elapsed
        };

        let top_attackers: HashMap<String, u64> = stats
            .top_attackers
            .iter()
            .map(|entry| {
                let ip = format_ip_key(entry.key());
                (ip, entry.value().load(Ordering::Relaxed))
            })
            .collect();

        let point = MetricPoint {
            timestamp: now,
            total_packets,
            total_passed,
            total_dropped,
            blacklist_blocked: stats.blacklist_blocked.load(Ordering::Relaxed),
            rate_limited: stats.rate_limited.load(Ordering::Relaxed),
            syn_flood_blocked: stats.syn_flood_blocked.load(Ordering::Relaxed),
            l7_blocked: stats.l7_blocked.load(Ordering::Relaxed),
            adaptive_blocked: stats.adaptive_blocked.load(Ordering::Relaxed),
            udp_flood_blocked: stats.udp_flood_blocked.load(Ordering::Relaxed),
            icmp_flood_blocked: stats.icmp_flood_blocked.load(Ordering::Relaxed),
            waf_blocked: stats.waf_blocked.load(Ordering::Relaxed),
            geoip_blocked: stats.geoip_blocked.load(Ordering::Relaxed),
            challenge_issued: stats.challenge_issued.load(Ordering::Relaxed),
            dps,
            pps,
            top_attackers,
        };

        if self.slots.len() == self.capacity {
            self.slots.remove(0);
        }
        self.slots.push(point);

        self.head_timestamp = now;
        self.last_total_packets = total_packets;
        self.last_total_dropped = total_dropped;
        self.last_total_passed = total_passed;
    }

    /// Return the most recent `duration_s` seconds of data.
    ///
    /// If `duration_s` is 0 or larger than the window capacity allows,
    /// returns all retained slots.
    pub fn snapshot(&self, duration_s: u64) -> Vec<MetricPoint> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(duration_s);

        if duration_s == 0 {
            return self.slots.clone();
        }

        self.slots
            .iter()
            .skip_while(|p| p.timestamp < cutoff)
            .cloned()
            .collect()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn make_stats(total_packets: u64, total_dropped: u64, total_passed: u64) -> Stats {
        Stats {
            total_packets: AtomicU64::new(total_packets),
            total_dropped: AtomicU64::new(total_dropped),
            total_passed: AtomicU64::new(total_passed),
            ..Stats::default()
        }
    }

    #[test]
    fn test_window_records_and_snapshots() {
        let mut window = TimeSeriesWindow::new(10, 10);
        let stats = make_stats(100, 10, 90);
        window.record(&stats);
        assert_eq!(window.snapshot(0).len(), 1);
    }

    #[test]
    fn test_window_drops_oldest_when_full() {
        let mut window = TimeSeriesWindow::new(2, 10);
        window.record(&make_stats(10, 1, 9));
        // Sleep 1s to ensure distinct timestamps
        std::thread::sleep(std::time::Duration::from_secs(1));
        window.record(&make_stats(20, 2, 18));
        std::thread::sleep(std::time::Duration::from_secs(1));
        window.record(&make_stats(30, 3, 27));

        let snap = window.snapshot(0);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].total_packets, 20);
        assert_eq!(snap[1].total_packets, 30);
    }
}

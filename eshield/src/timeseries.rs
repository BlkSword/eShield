use std::collections::HashMap;
use std::sync::atomic::Ordering;

use crate::time::monotonic_secs as monotonic_now_secs;

use crate::ip::format_ip_key;
use crate::state::Stats;

/// A single sampled metrics point.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
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
    pub geoip_blocked: u64,
    /// Derived: dropped packets per second since the previous point.
    /// `None` indicates that no packets were observed during this interval.
    pub dps: Option<u64>,
    /// Derived: passed packets per second since the previous point.
    /// `None` indicates that no packets were observed during this interval.
    pub pps: Option<u64>,
    /// Maximum observed DPS within the interval (currently equal to `dps`).
    #[serde(default)]
    pub dps_max: Option<u64>,
    /// Maximum observed PPS within the interval (currently equal to `pps`).
    #[serde(default)]
    pub pps_max: Option<u64>,
    /// Whether any packet was passed or dropped during the interval.
    #[serde(default)]
    pub has_data: bool,
    /// Snapshot of top attackers at this point: ip -> count.
    pub top_attackers: std::collections::HashMap<String, u64>,
    /// Snapshot of top attacked ports at this point: port -> count.
    pub port_dropped: std::collections::HashMap<u16, u64>,
}

/// Fixed-size in-memory ring buffer for time-series metrics.
///
/// Designed to be cheap enough to sample every few seconds from a tokio task
/// without introducing external TSDB dependencies for a single-node tool.
/// Default capacity 8640 slots at 10s interval retains 24 hours of data.
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
        let now = monotonic_now_secs();

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

        let dropped_delta = if self.head_timestamp == 0 {
            0
        } else {
            total_dropped.saturating_sub(self.last_total_dropped)
        };
        let passed_delta = if self.head_timestamp == 0 {
            0
        } else {
            total_passed.saturating_sub(self.last_total_passed)
        };
        let packet_delta = if self.head_timestamp == 0 {
            0
        } else {
            total_packets.saturating_sub(self.last_total_packets)
        };

        let has_data = self.head_timestamp != 0 && packet_delta > 0;
        let dps = if has_data {
            Some(dropped_delta / elapsed)
        } else {
            None
        };
        let pps = if has_data {
            Some(passed_delta / elapsed)
        } else {
            None
        };

        let top_attackers: HashMap<String, u64> = stats
            .top_attackers
            .iter()
            .map(|entry| {
                let ip = format_ip_key(entry.key());
                (ip, entry.value().load(Ordering::Relaxed))
            })
            .collect();

        let port_dropped: HashMap<u16, u64> = stats
            .port_dropped
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
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
            geoip_blocked: stats.geoip_blocked.load(Ordering::Relaxed),
            dps,
            pps,
            dps_max: dps,
            pps_max: pps,
            has_data,
            top_attackers,
            port_dropped,
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
        let cutoff = monotonic_now_secs().saturating_sub(duration_s);

        if duration_s == 0 {
            return self.slots.clone();
        }

        self.slots
            .iter()
            .skip_while(|p| p.timestamp < cutoff)
            .cloned()
            .collect()
    }

    /// 将持久化的点加载到窗口中。
    ///
    /// 只保留最近的 `capacity` 个点；最新点的时间戳作为下一次 `record()`
    /// 的间隔基准，但计数器基线归零——因为新进程里 eBPF 计数器从 0 开始。
    pub fn load(&mut self, points: Vec<MetricPoint>) {
        if points.is_empty() {
            return;
        }
        self.slots.clear();
        let start = points.len().saturating_sub(self.capacity);
        self.slots.extend(points.into_iter().skip(start));
        if let Some(last) = self.slots.last() {
            self.head_timestamp = last.timestamp;
            self.last_total_packets = 0;
            self.last_total_dropped = 0;
            self.last_total_passed = 0;
        }
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

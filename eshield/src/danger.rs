//! Danger Signal Monitor (v0.4.0)
//!
//! 周期性采样 CPU 使用率、内存使用率和全局 DPS，以 EWMA 维护基线，
//! 当实时值超过基线的 `anomaly_multiplier` 倍时，计算全局危险等级。
//!
//! 等级 0 (normal) → 防御参数不变
//! 等级 1 (elevated) → 速率阈值打 75 折
//! 等级 2 (critical) → 速率阈值打 5 折

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

/// 全局危险等级（写 eBPF CONFIG map 前，先在此缓存）。
#[derive(Debug)]
pub struct DangerMonitor {
    pub level: AtomicU8,
    cpu_ewma: Mutex<f64>,
    dps_ewma: Mutex<f64>,
    /// 上一次读取的 /proc/stat 原始值：(idle_total, cpu_total)
    prev_cpu: Mutex<(u64, u64)>,
    anomaly_multiplier: f64,
}

impl DangerMonitor {
    pub fn new(anomaly_multiplier: f64) -> Self {
        Self {
            level: AtomicU8::new(0),
            cpu_ewma: Mutex::new(0.0),
            dps_ewma: Mutex::new(0.0),
            prev_cpu: Mutex::new((0, 0)),
            anomaly_multiplier,
        }
    }

    /// 每 `sample_interval_s` 秒调用一次，返回 0/1/2。
    pub fn sample(&self, current_dps: u64) -> u8 {
        let cpu = self.read_cpu_usage();
        let mem = self.read_mem_usage();

        // EWMA 更新: baseline = 0.95 × old + 0.05 × new
        let mut cpu_ewma = self.cpu_ewma.lock().unwrap();
        *cpu_ewma = 0.95 * *cpu_ewma + 0.05 * cpu;
        let mut dps_ewma = self.dps_ewma.lock().unwrap();
        *dps_ewma = 0.95 * *dps_ewma + 0.05 * (current_dps as f64);

        // 异常判定：CPU > 50% 或 DPS > 1000，且超过 EWMA 基线 × 倍数
        let cpu_anomaly = cpu > *cpu_ewma * self.anomaly_multiplier && cpu > 500.0;
        let mem_anomaly = mem > 900.0; // >90% memory
        let dps_anomaly =
            (current_dps as f64) > *dps_ewma * self.anomaly_multiplier && current_dps > 1000;

        let level = if (cpu_anomaly && dps_anomaly) || mem_anomaly {
            2 // critical
        } else if cpu_anomaly || dps_anomaly {
            1 // elevated
        } else {
            0 // normal
        };

        self.level.store(level, Ordering::Relaxed);
        level
    }

    /// 读取 CPU 使用率（千分比，0-1000，100% 全核满）。
    fn read_cpu_usage(&self) -> f64 {
        let content = match std::fs::read_to_string("/proc/stat") {
            Ok(c) => c,
            Err(_) => return 0.0,
        };
        let line = match content.lines().find(|l| l.starts_with("cpu ")) {
            Some(l) => l,
            None => return 0.0,
        };
        let fields: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();
        if fields.len() < 4 {
            return 0.0;
        }
        // fields[3] = idle
        let total: u64 = fields.iter().sum();
        let idle = fields[3];

        let mut prev = self.prev_cpu.lock().unwrap();
        let (prev_idle, prev_total) = *prev;
        *prev = (total, idle);

        if prev_total == 0 {
            return 0.0;
        }
        let delta_total = total.saturating_sub(prev_total);
        let delta_idle = idle.saturating_sub(prev_idle);
        if delta_total == 0 {
            return 0.0;
        }
        // usage = 1.0 - idle_delta / total_delta，返回千分比
        (1.0 - delta_idle as f64 / delta_total as f64) * 1000.0
    }

    /// 读取内存使用率（千分比，0-1000）。
    fn read_mem_usage(&self) -> f64 {
        let content = match std::fs::read_to_string("/proc/meminfo") {
            Ok(c) => c,
            Err(_) => return 0.0,
        };
        let mut total = 0u64;
        let mut available = 0u64;
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                total = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if line.starts_with("MemAvailable:") {
                available = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        if total == 0 {
            return 0.0;
        }
        ((total - available) as f64 / total as f64) * 1000.0
    }
}

use aya::maps::HashMap as LruHashMap;
use aya::Ebpf;
use eshield_common::{rules, BlockEntry};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::AdaptiveConfig;
use crate::state::Stats;

/// 用户态自适应阈值引擎：根据 Ring Buffer 中的 DROP 事件，
/// 对短时间窗口内多次触发规则的源 IP 追加动态黑名单。
pub struct AdaptiveEngine {
    config: AdaptiveConfig,
    /// 每个 IP 的最近事件时间戳（秒），用于滑动窗口计数
    windows: dashmap::DashMap<u32, Vec<u64>>,
    /// 已自适应封禁的 IP 及其解封时间戳（秒）
    blocked: dashmap::DashMap<u32, u64>,
}

impl AdaptiveEngine {
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            config,
            windows: dashmap::DashMap::new(),
            blocked: dashmap::DashMap::new(),
        }
    }

    /// 处理一条 DROP 事件。如果命中阈值，写入 BLACKLIST map。
    pub fn on_event(&self, _stats: &Stats, src_ip: u32, ebpf: &mut Ebpf) -> anyhow::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let now_s = now_s();
        let window_s = self.config.window_s;
        let threshold = self.config.threshold;
        let block_duration_s = self.config.block_duration_s;

        // 已封禁且未过期则跳过
        if let Some(entry) = self.blocked.get(&src_ip) {
            if *entry > now_s {
                return Ok(());
            }
        }

        // 滑动窗口计数
        let mut window = self.windows.entry(src_ip).or_default();
        window.retain(|t| now_s.saturating_sub(*t) <= window_s);
        window.push(now_s);

        if window.len() as u64 >= threshold {
            let blocked_until_ns = if block_duration_s == 0 {
                0
            } else {
                let now_ns = now_ns();
                let block_ns = block_duration_s.saturating_mul(1_000_000_000);
                now_ns.saturating_add(block_ns)
            };

            let mut blacklist: LruHashMap<_, u32, BlockEntry> = ebpf
                .map_mut("BLACKLIST")
                .ok_or_else(|| anyhow::anyhow!("BLACKLIST map not found"))?
                .try_into()?;

            let entry = BlockEntry {
                blocked_until_ns,
                block_reason: rules::ADAPTIVE as u8,
                hit_count: 0,
                first_seen_ns: now_ns(),
            };
            blacklist.insert(src_ip, entry, 0)?;

            // 记录封禁截止时间，避免重复写入 map
            self.blocked.insert(src_ip, now_s.saturating_add(block_duration_s));

            tracing::info!(
                "adaptive block: src={} threshold={}/{}s duration={}s",
                format_addr(src_ip),
                threshold,
                window_s,
                block_duration_s
            );
        }

        Ok(())
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn format_addr(addr: u32) -> String {
    std::net::Ipv4Addr::from(addr.to_be_bytes()).to_string()
}

use crate::config::BlockOrigin;
use crate::store::RuleStore;
use anyhow::{Context, Result};
use aya::maps::HashMap as LruHashMap;
use aya::Ebpf;
use dashmap::DashMap;
use eshield_common::{rules, BlockEntry, IpKey};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// 缓存条目，用于避免对未变化的 eBPF BLACKLIST 条目反复写 store。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CachedEntry {
    blocked_until_ns: u64,
    hit_count: u32,
    block_reason: u8,
}

/// 把 eBPF BLACKLIST map 中由数据面检测模块写入的条目同步到持久化 store，
/// 使 rate_limit / syn_flood / udp_flood / icmp_flood / adaptive 等来源产生的
/// 动态黑名单能够被 Hub 客户端上报给集群其他节点。
pub struct BlacklistSync {
    ebpf: Arc<Mutex<Ebpf>>,
    store: RuleStore,
    interval: Duration,
    cache: DashMap<IpKey, CachedEntry>,
}

impl BlacklistSync {
    pub fn new(ebpf: Arc<Mutex<Ebpf>>, store: RuleStore, interval: Duration) -> Self {
        Self {
            ebpf,
            store,
            interval,
            cache: DashMap::new(),
        }
    }

    pub async fn run(&self) {
        let mut tick = tokio::time::interval(self.interval);
        loop {
            tick.tick().await;
            if let Err(e) = self.sync_once().await {
                warn!("blacklist sync failed: {}", e);
            }
        }
    }

    async fn sync_once(&self) -> Result<()> {
        let mut guard = self.ebpf.lock().await;
        let blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
            .map_mut("BLACKLIST")
            .context("BLACKLIST map not found")?
            .try_into()
            .context("failed to open BLACKLIST map")?;

        // 加载当前 store 中的来源信息。Hub 下发的策略在 store 里标记为 Hub，
        // 但 eBPF 里只保存了原始 rule_id；这里避免把它们覆盖成 Local 来源，
        // 否则 Hub DELETE 后节点无法识别哪些条目应该解封。
        let store_origins: std::collections::HashMap<IpKey, BlockOrigin> = self
            .store
            .load_blacklist()
            .await?
            .into_iter()
            .map(|(key, _, _, _, origin)| (key, origin))
            .collect();

        let mut synced = 0usize;
        let mut skipped = 0usize;

        for item in blacklist.iter().flatten() {
            let (key, entry) = (item.0, item.1);
            let origin = match block_reason_to_origin(entry.block_reason) {
                Some(o) => o,
                None => {
                    skipped += 1;
                    continue;
                }
            };

            if !origin.publishable() {
                skipped += 1;
                continue;
            }

            // 若 store 中已存在 Hub 来源的条目，保留 Hub 来源，避免本地检测模块
            // 的 rule_id 把来源覆盖成 Local。
            if origin != BlockOrigin::Hub {
                if let Some(&store_origin) = store_origins.get(&key) {
                    if store_origin == BlockOrigin::Hub {
                        skipped += 1;
                        continue;
                    }
                }
            }

            let cached = CachedEntry {
                blocked_until_ns: entry.blocked_until_ns,
                hit_count: entry.hit_count,
                block_reason: entry.block_reason,
            };

            if let Some(existing) = self.cache.get(&key) {
                if *existing == cached {
                    continue;
                }
            }

            self.store
                .save_blacklist(
                    key,
                    entry.blocked_until_ns,
                    entry.block_reason,
                    entry.first_seen_ns,
                    origin,
                )
                .await?;

            self.cache.insert(key, cached);
            synced += 1;
        }

        drop(guard);

        if synced > 0 {
            debug!(synced, skipped, "blacklist map synced to store");
        }
        Ok(())
    }
}

fn block_reason_to_origin(reason: u8) -> Option<BlockOrigin> {
    match reason as u16 {
        rules::RATE_LIMIT | rules::SYN_FLOOD | rules::UDP_FLOOD | rules::ICMP_FLOOD => {
            Some(BlockOrigin::Local)
        }
        rules::ADAPTIVE => Some(BlockOrigin::Adaptive),
        rules::API_BLOCK => Some(BlockOrigin::Api),
        rules::THREAT_INTEL => Some(BlockOrigin::ThreatIntel),
        _ => None,
    }
}

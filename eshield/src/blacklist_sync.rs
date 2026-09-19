use crate::config::BlockOrigin;
use crate::store::RuleStore;
use anyhow::{Context, Result};
use aya::maps::HashMap as LruHashMap;
use aya::Ebpf;
use dashmap::DashMap;
use eshield_common::{rules, BlockEntry, IpKey};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// 上次清理过期持久化黑名单的时间（ns）。
    last_prune_ns: AtomicU64,
}

impl BlacklistSync {
    pub fn new(ebpf: Arc<Mutex<Ebpf>>, store: RuleStore, interval: Duration) -> Self {
        Self {
            ebpf,
            store,
            interval,
            cache: DashMap::new(),
            last_prune_ns: AtomicU64::new(0),
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
        let now_ns = crate::time::monotonic_ns();

        // 只在锁内做一次快照，随后释放 eBPF Mutex 再做持久化写入，
        // 避免逐条 redb 事务长期占用锁、阻塞事件消费/控制面。
        let snapshot: Vec<(IpKey, BlockEntry)> = {
            let mut guard = self.ebpf.lock().await;
            let blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
                .map_mut("BLACKLIST")
                .context("BLACKLIST map not found")?
                .try_into()
                .context("failed to open BLACKLIST map")?;
            blacklist
                .iter()
                .flatten()
                .map(|(key, entry)| (key, entry))
                .collect()
        };

        let mut skipped = 0usize;
        let mut changed: Vec<(IpKey, BlockEntry, BlockOrigin, CachedEntry)> = Vec::new();

        for (key, entry) in snapshot {
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
            changed.push((key, entry, origin, cached));
        }

        let mut synced = 0usize;
        if !changed.is_empty() {
            // 只有确实存在变更时才加载 store 来源信息；空闲时避免每 5s 全量扫描 redb。
            let store_origins: std::collections::HashMap<IpKey, BlockOrigin> = self
                .store
                .load_blacklist()
                .await?
                .into_iter()
                .map(|(key, _, _, _, origin)| (key, origin))
                .collect();

            for (key, entry, origin, cached) in changed {
                // Hub 下发的策略在 store 里标记为 Hub，但 eBPF 只保存 rule_id；
                // 避免本地检测模块的 rule_id 把来源覆盖成 Local，导致 Hub DELETE 无法解封。
                if origin != BlockOrigin::Hub {
                    if let Some(&store_origin) = store_origins.get(&key) {
                        if store_origin == BlockOrigin::Hub {
                            skipped += 1;
                            continue;
                        }
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
        }

        // 每 60s 清理一次已过期的持久化动态黑名单，避免 redb 只增不减。
        let last_prune = self.last_prune_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(last_prune) >= 60_000_000_000 {
            match self.store.prune_expired_blacklist(now_ns).await {
                Ok(pruned) if pruned > 0 => debug!(pruned, "pruned expired persisted blacklist"),
                Ok(_) => {}
                Err(e) => warn!("failed to prune persisted blacklist: {}", e),
            }
            self.last_prune_ns.store(now_ns, Ordering::Relaxed);
        }

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

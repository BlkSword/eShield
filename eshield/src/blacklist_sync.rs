use crate::config::BlockOrigin;
use crate::store::RuleStore;
use anyhow::{Context, Result};
use aya::maps::HashMap as LruHashMap;
use aya::maps::PerCpuArray;
use aya::Ebpf;
use dashmap::DashMap;
use eshield_common::{rules, BlockEntry, GlobalStats, IpKey};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, warn};

type SyncScan = (Option<(u64, u64)>, Vec<(IpKey, BlockEntry)>, bool);

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
    /// 上次同步时 eBPF 黑名单“新增”代数；变化时立即全量扫描。
    last_gen: AtomicU64,
    /// 上次同步时 eBPF 黑名单“命中”代数；仅按 60s 降频扫描。
    last_hit_gen: AtomicU64,
    /// 上次因 hit_count 变化而扫描的时间（ns）。
    last_hit_scan_ns: AtomicU64,
}

impl BlacklistSync {
    pub fn new(ebpf: Arc<Mutex<Ebpf>>, store: RuleStore, interval: Duration) -> Self {
        Self {
            ebpf,
            store,
            interval,
            cache: DashMap::new(),
            last_prune_ns: AtomicU64::new(0),
            last_gen: AtomicU64::new(0),
            last_hit_gen: AtomicU64::new(0),
            last_hit_scan_ns: AtomicU64::new(0),
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

        // 新增黑名单立即扫描；仅 hit_count 变化时降频到 60s 扫描，
        // 避免攻击期间每 5s 全量遍历 10 万条 BLACKLIST。
        let (gens, snapshot, scanned): SyncScan = {
            let mut guard = self.ebpf.lock().await;
            let gens = read_blacklist_gens(&mut guard);
            let add_changed = gens
                .map(|(add, _)| add != self.last_gen.load(Ordering::Relaxed))
                .unwrap_or(true);
            let hit_changed = gens
                .map(|(_, hit)| hit != self.last_hit_gen.load(Ordering::Relaxed))
                .unwrap_or(false);
            let hit_due = now_ns.saturating_sub(self.last_hit_scan_ns.load(Ordering::Relaxed))
                >= 60_000_000_000;
            let need_scan =
                gens.is_none() || add_changed || (hit_changed && hit_due) || self.cache.is_empty();
            if need_scan {
                let blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
                    .map_mut("BLACKLIST")
                    .context("BLACKLIST map not found")?
                    .try_into()
                    .context("failed to open BLACKLIST map")?;
                (gens, blacklist.iter().flatten().collect(), true)
            } else {
                (gens, Vec::new(), false)
            }
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
            let changed_keys: Vec<IpKey> = changed.iter().map(|(key, _, _, _)| *key).collect();
            let store_origins = self.store.load_blacklist_origins(&changed_keys).await?;

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

        if scanned {
            if let Some((add_gen, hit_gen)) = gens {
                self.last_gen.store(add_gen, Ordering::Relaxed);
                self.last_hit_gen.store(hit_gen, Ordering::Relaxed);
                self.last_hit_scan_ns.store(now_ns, Ordering::Relaxed);
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

/// 读取 eBPF GLOBAL_STATS 中所有 CPU 的黑名单新增/命中代数之和。
fn read_blacklist_gens(ebpf: &mut Ebpf) -> Option<(u64, u64)> {
    let map = ebpf.map_mut("GLOBAL_STATS")?;
    let global: PerCpuArray<_, GlobalStats> = map.try_into().ok()?;
    let values = global.get(&0, 0).ok()?;
    let add_gen = values.iter().map(|v| v.blacklist_gen).sum();
    let hit_gen = values.iter().map(|v| v.blacklist_hit_gen).sum();
    Some((add_gen, hit_gen))
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

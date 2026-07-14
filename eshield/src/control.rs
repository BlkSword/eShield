use anyhow::Context;
use aya::{
    maps::{lpm_trie::Key as LpmKey, Array, HashMap as LruHashMap, LpmTrie},
    Ebpf,
};
use eshield_common::{
    rules, BlockEntry, GeoIpKeyV4, GeoIpKeyV6, IpFamily, IpKey, L7Pattern, PortAclEntry,
    RateLimitConfig, RuntimeConfig, TrustEntry, WhitelistKeyV4, WhitelistKeyV6, BLOCK_PERMANENT,
};

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

use crate::adaptive::AdaptiveEngine;
use crate::audit::{AuditAction, Auditor};
use crate::config::{
    Config, GeoIpConfig, L7ScanConfig, PortAclItem, ProtectionProject, ThreatFeed,
};
use crate::hub_client::{NodePolicy, SharedPolicy};
use crate::ip::{format_ip_key, parse_cidr, parse_ip_or_cidr};
use crate::store::RuleStore;

/// 控制面共享状态，Web / CLI / SIGHUP 都通过它操作 eBPF Maps。
pub struct ControlState {
    pub ebpf: Arc<Mutex<Ebpf>>,
    pub config_path: String,
    pub runtime: RwLock<RuntimeConfigSnapshot>,
    pub whitelist: Mutex<Vec<(IpKey, u32)>>,
    pub blacklist: Mutex<Vec<IpKey>>,
    pub geoip_blocks: Mutex<Vec<(IpKey, u32)>>,
    pub auditor: Option<Auditor>,
    pub store: Option<RuleStore>,
    pub hub_connected: std::sync::atomic::AtomicBool,
    pub hub_active_url: std::sync::Mutex<String>,
    pub hub_config: crate::config::HubConfig,
    adaptive: Option<Arc<AdaptiveEngine>>,
}

/// 运行时可读快照（用于 Web / CLI 展示）。
#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeConfigSnapshot {
    pub version: String,
    pub interface: String,
    pub web_port: u16,
    pub web_bind: Option<String>,
    pub log_level: String,
    pub log_json: bool,
    pub store_path: String,
    pub alert_webhook_url: Option<String>,
    pub alert_threshold_dps: u64,
    pub alert_cooldown_s: u64,
    pub rate_limit_enabled: bool,
    pub syn_proxy_enabled: bool,
    pub l7_scan_enabled: bool,
    pub ebpf_debug_enabled: bool,
    pub udp_flood_enabled: bool,
    pub icmp_flood_enabled: bool,
    pub geoip_enabled: bool,
    pub tcp_reset_on_drop: bool,
    pub trust_enabled: bool,
    pub danger_level: u8,
    pub rate_limit: RateLimitParams,
    pub adaptive: crate::config::AdaptiveConfig,
    pub port_acl: Vec<PortAclItem>,
    pub protection_projects: Vec<ProtectionProject>,
    pub l7_scan: L7ScanConfig,
    pub geoip: GeoIpConfig,
    pub threat_intel_feeds: Vec<ThreatFeed>,
    pub whitelist_entries: Vec<String>,
    pub blacklist_entries: Vec<String>,
    pub hub_enabled: bool,
    pub hub_node_name: String,
    pub hub_urls: Vec<String>,
    pub packet_log_enabled: bool,
    pub packet_log_sample_rate: u16,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RateLimitParams {
    pub enabled: bool,
    pub threshold: u64,
    pub tick_ms: u64,
    pub decay_num: u64,
    pub decay_den: u64,
    pub block_duration_s: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuntimeConfigPatch {
    pub rate_limit_enabled: Option<bool>,
    pub syn_proxy_enabled: Option<bool>,
    pub l7_scan_enabled: Option<bool>,
    pub ebpf_debug_enabled: Option<bool>,
    pub udp_flood_enabled: Option<bool>,
    pub icmp_flood_enabled: Option<bool>,
    pub geoip_enabled: Option<bool>,
    pub tcp_reset_on_drop: Option<bool>,
    pub trust_enabled: Option<bool>,
    pub rate_limit: Option<RateLimitParams>,
    pub adaptive: Option<crate::config::AdaptiveConfig>,
}

impl ControlState {
    pub async fn new(
        ebpf: Arc<Mutex<Ebpf>>,
        config_path: String,
        config: &Config,
        auditor: Option<Auditor>,
        store: Option<RuleStore>,
        adaptive: Option<Arc<AdaptiveEngine>>,
    ) -> anyhow::Result<Self> {
        let state = Self {
            ebpf,
            config_path,
            runtime: RwLock::new(RuntimeConfigSnapshot::from_config(config)),
            whitelist: Mutex::new(Vec::new()),
            blacklist: Mutex::new(Vec::new()),
            geoip_blocks: Mutex::new(Vec::new()),
            auditor,
            store,
            hub_connected: std::sync::atomic::AtomicBool::new(false),
            hub_active_url: std::sync::Mutex::new(String::new()),
            hub_config: config.hub.clone(),
            adaptive,
        };

        // 初始化运行时配置与策略
        {
            let mut guard = state.ebpf.lock().await;
            init_config_map(&mut guard, config)?;
            init_rate_limit_map(&mut guard, config)?;
            init_l7_patterns_map(&mut guard, &config.l7_scan.patterns)?;
            init_port_acl_map(&mut guard, &config.port_acl)?;
            init_protection_projects_map(&mut guard, &config.protection_projects)?;
            let mut blacklist = state.blacklist.lock().await;
            let mut whitelist = state.whitelist.lock().await;
            let mut geoip_blocks = state.geoip_blocks.lock().await;
            apply_blacklist_map(&mut guard, config, &mut blacklist).await?;
            apply_whitelist_map(&mut guard, config, &mut whitelist).await?;
            apply_geoip_map(&mut guard, config, &mut geoip_blocks).await?;
        }

        Ok(state)
    }

    /// 从配置文件重新加载全部策略。
    pub async fn reload_config_file(&self) -> anyhow::Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let mut guard = self.ebpf.lock().await;
        let mut whitelist = self.whitelist.lock().await;
        let mut blacklist = self.blacklist.lock().await;
        let mut geoip_blocks = self.geoip_blocks.lock().await;

        init_config_map(&mut guard, &config)?;
        init_rate_limit_map(&mut guard, &config)?;
        init_l7_patterns_map(&mut guard, &config.l7_scan.patterns)?;
        init_port_acl_map(&mut guard, &config.port_acl)?;
        init_protection_projects_map(&mut guard, &config.protection_projects)?;
        apply_whitelist_map(&mut guard, &config, &mut whitelist).await?;
        apply_blacklist_map(&mut guard, &config, &mut blacklist).await?;
        apply_geoip_map(&mut guard, &config, &mut geoip_blocks).await?;

        *self.runtime.write().await = RuntimeConfigSnapshot::from_config(&config);
        if let Some(adaptive) = &self.adaptive {
            adaptive.update_config(config.adaptive.clone());
        }
        drop(guard);
        drop(whitelist);
        drop(blacklist);

        // 重新应用持久化的动态规则，避免配置文件覆盖 API/自适应 产生的规则
        if let Err(e) = self.load_persisted_rules().await {
            tracing::warn!("failed to reload persisted rules: {}", e);
        }

        self.audit("system", AuditAction::ReloadConfig, serde_json::json!({}))
            .await;
        Ok(())
    }

    /// 实时封禁某个 IP（API 控制）。支持 IPv4/IPv6。
    pub async fn block_ip(&self, ip_str: &str, duration_s: u64) -> anyhow::Result<()> {
        let key = parse_ip_or_cidr(ip_str)?;
        self.block_ip_key(
            key,
            duration_s,
            rules::API_BLOCK as u8,
            crate::config::BlockOrigin::Api,
        )
        .await?;
        info!("API block: {} duration={}s", ip_str, duration_s);
        Ok(())
    }

    /// 通过威胁情报 feed 封禁某个 IP。
    pub async fn block_ip_threat_intel(&self, key: IpKey, duration_s: u64) -> anyhow::Result<()> {
        self.block_ip_key(
            key,
            duration_s,
            rules::THREAT_INTEL as u8,
            crate::config::BlockOrigin::ThreatIntel,
        )
        .await?;
        info!(
            "threat intel block: {} duration={}s",
            format_ip_key(&key),
            duration_s
        );
        Ok(())
    }

    /// 通用封禁接口，供 API / 自适应 / 威胁情报 / Hub 下发使用。
    pub async fn block_ip_key(
        &self,
        key: IpKey,
        duration_s: u64,
        reason: u8,
        origin: crate::config::BlockOrigin,
    ) -> anyhow::Result<()> {
        self.block_ip_raw(key, duration_s, reason).await?;

        if let Some(store) = &self.store {
            let now_ns = crate::time::monotonic_ns();
            let blocked_until_ns = if duration_s == 0 {
                BLOCK_PERMANENT
            } else {
                let block_ns = duration_s.saturating_mul(1_000_000_000);
                now_ns.saturating_add(block_ns)
            };
            store
                .save_blacklist(key, blocked_until_ns, reason, now_ns, origin)
                .await?;
        }

        let actor = match origin {
            crate::config::BlockOrigin::Api => "api",
            crate::config::BlockOrigin::Adaptive => "adaptive",
            crate::config::BlockOrigin::ThreatIntel => "threat_intel",
            crate::config::BlockOrigin::Hub => "hub",
            crate::config::BlockOrigin::Local => "local",
        };
        self.audit(
            actor,
            AuditAction::BlockIp,
            serde_json::json!({ "ip": format_ip_key(&key), "duration_s": duration_s, "origin": origin }),
        )
        .await;
        Ok(())
    }

    async fn block_ip_raw(&self, key: IpKey, duration_s: u64, reason: u8) -> anyhow::Result<()> {
        let mut guard = self.ebpf.lock().await;
        let mut blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
            .map_mut("BLACKLIST")
            .context("BLACKLIST map not found")?
            .try_into()?;

        let blocked_until_ns = if duration_s == 0 {
            BLOCK_PERMANENT
        } else {
            let now_ns = crate::time::monotonic_ns();
            let block_ns = duration_s.saturating_mul(1_000_000_000);
            now_ns.saturating_add(block_ns)
        };

        blacklist.insert(
            key,
            BlockEntry {
                blocked_until_ns,
                block_reason: reason,
                hit_count: 0,
                first_seen_ns: crate::time::monotonic_ns(),
            },
            0,
        )?;
        Ok(())
    }

    /// 实时解封某个 IP。
    pub async fn unblock_ip(&self, ip_str: &str) -> anyhow::Result<()> {
        let key = parse_ip_or_cidr(ip_str)?;
        self.unblock_ip_key(key, "api").await?;
        info!("API unblock: {}", ip_str);
        Ok(())
    }

    /// 按 IpKey 解封，供 Hub 删除同步等内部路径使用。
    pub async fn unblock_ip_key(&self, key: IpKey, actor: &str) -> anyhow::Result<()> {
        let mut guard = self.ebpf.lock().await;
        let mut blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
            .map_mut("BLACKLIST")
            .context("BLACKLIST map not found")?
            .try_into()?;
        blacklist.remove(&key)?;
        drop(guard);

        self.blacklist.lock().await.retain(|&x| x != key);

        if let Some(store) = &self.store {
            store.remove_blacklist(key).await?;
        }

        self.audit(
            actor,
            AuditAction::UnblockIp,
            serde_json::json!({ "ip": format_ip_key(&key) }),
        )
        .await;
        Ok(())
    }

    /// 实时放行某个 CIDR。
    pub async fn allow_cidr(&self, cidr: &str) -> anyhow::Result<()> {
        let (key, prefix) = parse_cidr(cidr)?;
        self.allow_cidr_raw(key, prefix).await?;

        if let Some(store) = &self.store {
            store.save_whitelist(key, prefix).await?;
        }

        self.audit(
            "api",
            AuditAction::AllowCidr,
            serde_json::json!({ "cidr": cidr }),
        )
        .await;
        info!("API whitelist add: {}", cidr);
        Ok(())
    }

    pub(crate) async fn allow_cidr_raw(&self, key: IpKey, prefix: u32) -> anyhow::Result<()> {
        let mut guard = self.ebpf.lock().await;

        match key.family() {
            Some(IpFamily::Ipv4) => {
                let mut whitelist: LpmTrie<_, WhitelistKeyV4, u8> = guard
                    .map_mut("WHITELIST_V4")
                    .context("WHITELIST_V4 map not found")?
                    .try_into()?;
                whitelist.insert(
                    &LpmKey::new(
                        prefix,
                        WhitelistKeyV4 {
                            addr: key.ipv4().to_be(),
                        },
                    ),
                    1,
                    0,
                )?;
            }
            Some(IpFamily::Ipv6) => {
                let mut whitelist: LpmTrie<_, WhitelistKeyV6, u8> = guard
                    .map_mut("WHITELIST_V6")
                    .context("WHITELIST_V6 map not found")?
                    .try_into()?;
                whitelist.insert(
                    &LpmKey::new(prefix, WhitelistKeyV6 { addr: key.addr }),
                    1,
                    0,
                )?;
            }
            _ => anyhow::bail!("unknown IP family"),
        }
        Ok(())
    }

    /// 实时移除某个 CIDR 放行。
    pub async fn disallow_cidr(&self, cidr: &str) -> anyhow::Result<()> {
        let (key, prefix) = parse_cidr(cidr)?;
        let mut guard = self.ebpf.lock().await;

        match key.family() {
            Some(IpFamily::Ipv4) => {
                let mut whitelist: LpmTrie<_, WhitelistKeyV4, u8> = guard
                    .map_mut("WHITELIST_V4")
                    .context("WHITELIST_V4 map not found")?
                    .try_into()?;
                whitelist.remove(&LpmKey::new(
                    prefix,
                    WhitelistKeyV4 {
                        addr: key.ipv4().to_be(),
                    },
                ))?;
            }
            Some(IpFamily::Ipv6) => {
                let mut whitelist: LpmTrie<_, WhitelistKeyV6, u8> = guard
                    .map_mut("WHITELIST_V6")
                    .context("WHITELIST_V6 map not found")?
                    .try_into()?;
                whitelist.remove(&LpmKey::new(prefix, WhitelistKeyV6 { addr: key.addr }))?;
            }
            _ => anyhow::bail!("unknown IP family"),
        }
        drop(guard);

        self.whitelist.lock().await.retain(|&x| x != (key, prefix));

        if let Some(store) = &self.store {
            store.remove_whitelist(key, prefix).await?;
        }

        self.audit(
            "api",
            AuditAction::DisallowCidr,
            serde_json::json!({ "cidr": cidr }),
        )
        .await;
        info!("API whitelist remove: {}", cidr);
        Ok(())
    }

    /// 热更新部分运行时开关与速率限制参数。
    pub async fn patch_runtime(&self, patch: RuntimeConfigPatch) -> anyhow::Result<()> {
        let mut snapshot = self.runtime.read().await.clone();

        if let Some(enabled) = patch.rate_limit_enabled {
            snapshot.rate_limit_enabled = enabled;
            snapshot.rate_limit.enabled = enabled;
        }
        if let Some(enabled) = patch.syn_proxy_enabled {
            snapshot.syn_proxy_enabled = enabled;
        }
        if let Some(enabled) = patch.l7_scan_enabled {
            snapshot.l7_scan_enabled = enabled;
        }
        if let Some(enabled) = patch.ebpf_debug_enabled {
            snapshot.ebpf_debug_enabled = enabled;
        }
        if let Some(enabled) = patch.udp_flood_enabled {
            snapshot.udp_flood_enabled = enabled;
        }
        if let Some(enabled) = patch.icmp_flood_enabled {
            snapshot.icmp_flood_enabled = enabled;
        }
        if let Some(enabled) = patch.geoip_enabled {
            snapshot.geoip_enabled = enabled;
        }
        if let Some(enabled) = patch.tcp_reset_on_drop {
            snapshot.tcp_reset_on_drop = enabled;
        }
        if let Some(enabled) = patch.trust_enabled {
            snapshot.trust_enabled = enabled;
        }
        if let Some(ref adaptive_cfg) = patch.adaptive {
            snapshot.adaptive = adaptive_cfg.clone();
            if let Some(adaptive) = &self.adaptive {
                adaptive.update_config(adaptive_cfg.clone());
            }
        }

        let mut guard = self.ebpf.lock().await;

        if let Some(ref rl) = patch.rate_limit {
            snapshot.rate_limit = rl.clone();
            snapshot.rate_limit_enabled = rl.enabled;
            let mut rate_cfg: Array<_, RateLimitConfig> = guard
                .map_mut("RATE_LIMIT_CFG")
                .context("RATE_LIMIT_CFG map not found")?
                .try_into()?;
            rate_cfg.set(
                0,
                RateLimitConfig {
                    threshold: rl.threshold,
                    tick_ms: rl.tick_ms,
                    decay_num: rl.decay_num,
                    decay_den: rl.decay_den,
                    block_duration_s: rl.block_duration_s,
                },
                0,
            )?;
        }

        {
            let mut config_array: Array<_, RuntimeConfig> = guard
                .map_mut("CONFIG")
                .context("CONFIG map not found")?
                .try_into()?;
            config_array.set(
                0,
                RuntimeConfig {
                    rate_limit_enabled: u8::from(snapshot.rate_limit_enabled),
                    syn_proxy_enabled: u8::from(snapshot.syn_proxy_enabled),
                    l7_scan_enabled: u8::from(snapshot.l7_scan_enabled),
                    ebpf_debug: u8::from(snapshot.ebpf_debug_enabled),
                    udp_flood_enabled: u8::from(snapshot.udp_flood_enabled),
                    icmp_flood_enabled: u8::from(snapshot.icmp_flood_enabled),
                    geoip_enabled: u8::from(snapshot.geoip_enabled),
                    tcp_reset_on_drop: u8::from(snapshot.tcp_reset_on_drop),
                    trust_enabled: u8::from(snapshot.trust_enabled),
                    danger_level: 0,
                    packet_log_enabled: u8::from(snapshot.packet_log_enabled),
                    packet_log_sample_rate: snapshot.packet_log_sample_rate,
                    padding: [0; 3],
                },
                0,
            )?;
        }

        *self.runtime.write().await = snapshot;

        self.audit(
            "api",
            AuditAction::PatchConfig,
            serde_json::json!({ "patch": patch }),
        )
        .await;
        Ok(())
    }

    /// 重新加载 GeoIP CSV 并应用。
    pub async fn reload_geoip(&self) -> anyhow::Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let mut guard = self.ebpf.lock().await;
        let mut geoip_blocks = self.geoip_blocks.lock().await;
        apply_geoip_map(&mut guard, &config, &mut geoip_blocks).await?;
        self.runtime.write().await.geoip = config.geoip.clone();
        self.audit(
            "api",
            AuditAction::PatchConfig,
            serde_json::json!({"geoip": config.geoip}),
        )
        .await;
        info!("GeoIP reloaded");
        Ok(())
    }

    /// 完全替换当前 L7 指纹模式，更新 eBPF Map、运行时快照与持久化存储。
    pub async fn set_l7_patterns(
        &self,
        patterns: Vec<crate::config::L7PatternConfig>,
    ) -> anyhow::Result<()> {
        {
            let mut guard = self.ebpf.lock().await;
            init_l7_patterns_map(&mut guard, &patterns)?;
        }

        self.runtime.write().await.l7_scan.patterns = patterns.clone();

        if let Some(store) = &self.store {
            store.save_l7_patterns(&patterns).await?;
        }

        self.audit(
            "api",
            AuditAction::PatchConfig,
            serde_json::json!({ "l7_patterns": patterns }),
        )
        .await;
        info!("L7 patterns updated: count={}", patterns.len());
        Ok(())
    }

    /// 完全替换当前端口 ACL，更新 eBPF Map、运行时快照与持久化存储。
    pub async fn set_port_acl(&self, items: Vec<PortAclItem>) -> anyhow::Result<()> {
        {
            let mut guard = self.ebpf.lock().await;
            init_port_acl_map(&mut guard, &items)?;
        }

        self.runtime.write().await.port_acl = items.clone();

        if let Some(store) = &self.store {
            store.save_port_acl_items(&items).await?;
        }

        self.audit(
            "api",
            AuditAction::PatchConfig,
            serde_json::json!({ "port_acl": items }),
        )
        .await;
        info!("port ACL updated: count={}", items.len());
        Ok(())
    }

    /// 完全替换当前防护项目，更新 eBPF Map、运行时快照与持久化存储。
    pub async fn set_protection_projects(
        &self,
        projects: Vec<ProtectionProject>,
    ) -> anyhow::Result<()> {
        {
            let mut guard = self.ebpf.lock().await;
            init_protection_projects_map(&mut guard, &projects)?;
        }

        self.runtime.write().await.protection_projects = projects.clone();

        if let Some(store) = &self.store {
            store.save_protection_projects(&projects).await?;
        }

        self.audit(
            "api",
            AuditAction::PatchConfig,
            serde_json::json!({ "protection_projects": projects }),
        )
        .await;
        info!("protection projects updated: count={}", projects.len());
        Ok(())
    }

    /// 从持久化存储加载动态规则并应用（不记录审计，避免启动/重载时产生大量日志）。
    pub async fn load_persisted_rules(&self) -> anyhow::Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };

        let now_ns = crate::time::monotonic_ns();
        for (key, blocked_until_ns, reason, _first_seen_ns, _origin) in
            store.load_blacklist().await?
        {
            // 静态黑名单由配置文件管理，不重复从持久化存储加载，避免旧配置残留。
            if reason == rules::BLACKLIST as u8 {
                continue;
            }
            // 已过期则跳过（BLOCK_PERMANENT 永不过期）
            if blocked_until_ns != BLOCK_PERMANENT && blocked_until_ns <= now_ns {
                continue;
            }
            let duration_s = if blocked_until_ns == BLOCK_PERMANENT {
                0
            } else {
                blocked_until_ns.saturating_sub(now_ns) / 1_000_000_000
            };
            self.block_ip_raw(key, duration_s, reason).await?;
        }

        for (key, prefix) in store.load_whitelist().await? {
            self.allow_cidr_raw(key, prefix).await?;
        }

        if let Ok(items) = store.load_port_acl_items().await {
            if !items.is_empty() {
                self.set_port_acl(items).await?;
            }
        }

        if let Ok(patterns) = store.load_l7_patterns().await {
            if !patterns.is_empty() {
                self.set_l7_patterns(patterns).await?;
            }
        }

        if let Ok(projects) = store.load_protection_projects().await {
            if !projects.is_empty() {
                self.set_protection_projects(projects).await?;
            }
        }

        Ok(())
    }

    /// 收集可上报给 Hub 的本地策略。
    pub async fn collect_hub_publishable_policies(
        &self,
        since_ns: u64,
        min_hits: u32,
        min_trust: u32,
        limit: usize,
    ) -> anyhow::Result<Vec<NodePolicy>> {
        let store = match &self.store {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let candidates = store.load_blacklist_since(since_ns).await?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        // 一次性读取 BLACKLIST 命中次数，然后释放该 map 的借用，再去读 TRUST_MAP。
        let mut hits = Vec::with_capacity(candidates.len());
        {
            let mut guard = self.ebpf.lock().await;
            let blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
                .map_mut("BLACKLIST")
                .context("BLACKLIST map not found")?
                .try_into()?;
            for (key, blocked_until_ns, reason, first_seen_ns, origin) in candidates {
                if !origin.publishable() {
                    continue;
                }
                let hit_count = match blacklist.get(&key, 0) {
                    Ok(entry) => entry.hit_count,
                    Err(_) => continue,
                };
                hits.push((
                    key,
                    blocked_until_ns,
                    reason,
                    first_seen_ns,
                    origin,
                    hit_count,
                ));
            }
        }

        let mut out = Vec::new();
        let now_ns = crate::time::monotonic_ns();

        for (key, blocked_until_ns, reason, _first_seen_ns, _origin, hit_count) in hits {
            // 命中次数不足且不是永久/长期封禁则跳过
            if hit_count < min_hits && blocked_until_ns <= now_ns {
                continue;
            }
            let trust_score = self.lookup_trust_score(&key).await;
            if trust_score > min_trust {
                continue;
            }
            let ttl_s = if blocked_until_ns == BLOCK_PERMANENT {
                0
            } else {
                blocked_until_ns.saturating_sub(now_ns) / 1_000_000_000
            };
            out.push(NodePolicy {
                ip: key,
                reason,
                hit_count,
                trust_score,
                blocked_until_ns,
                ttl_s,
            });
            if out.len() >= limit {
                break;
            }
        }

        Ok(out)
    }

    /// 从 eBPF TRUST_MAP 读取指定 IP 的信誉分，缩放为 0-100（与 Hub 协议一致）。
    async fn lookup_trust_score(&self, key: &IpKey) -> u32 {
        let mut guard = self.ebpf.lock().await;
        let m = match guard.map_mut("TRUST_MAP") {
            Some(m) => m,
            None => return 0,
        };
        let trust_map = match LruHashMap::<_, IpKey, TrustEntry>::try_from(m) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("failed to open TRUST_MAP: {}", e);
                return 0;
            }
        };
        match trust_map.get(key, 0) {
            Ok(entry) => (entry.trust_score / 10).min(100),
            Err(_) => 0,
        }
    }

    /// 应用从 Hub 拉取下来的共享策略。
    pub async fn apply_hub_policies(&self, policies: &[SharedPolicy]) -> anyhow::Result<usize> {
        if policies.is_empty() {
            return Ok(0);
        }

        // 一次性读取本地已有黑名单，避免后续重复加锁
        let existing: HashSet<IpKey> = {
            let mut guard = self.ebpf.lock().await;
            let blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
                .map_mut("BLACKLIST")
                .context("BLACKLIST map not found")?
                .try_into()?;
            let mut set = HashSet::new();
            for (key, _) in blacklist.iter().flatten() {
                set.insert(key);
            }
            set
        };

        let mut applied = 0usize;

        let node_name = &self.hub_config.node_name;
        for policy in policies {
            if existing.contains(&policy.ip) {
                continue;
            }

            // 跳过源自本节点的策略，避免本地封禁被 Hub 回传后永远无法自动解封。
            if !node_name.is_empty() && policy.source_nodes.iter().any(|n| n == node_name) {
                tracing::debug!(
                    ip = ?policy.ip,
                    "skip hub policy originating from this node"
                );
                continue;
            }

            // Hub 下发的共享策略使用 ttl_s 描述希望封禁的时长。
            let duration_s = policy.ttl_s.max(60); // 至少封禁 60s，避免过期

            self.block_ip_key(
                policy.ip,
                duration_s,
                policy.reason,
                crate::config::BlockOrigin::Hub,
            )
            .await?;

            // 将 Hub 聚合后的信誉分同步到本地 TRUST_MAP，供数据面调制阈值。
            if policy.trust_score > 0 {
                self.set_trust_score(policy.ip, policy.trust_score * 10)
                    .await;
            }

            applied += 1;
        }

        Ok(applied)
    }

    /// 将指定 IP 的信誉分写入 eBPF TRUST_MAP。
    async fn set_trust_score(&self, key: IpKey, trust_score: u32) {
        let trust_enabled = self.runtime.read().await.trust_enabled;
        if !trust_enabled {
            return;
        }
        let mut guard = self.ebpf.lock().await;
        let m = match guard.map_mut("TRUST_MAP") {
            Some(m) => m,
            None => {
                tracing::debug!("TRUST_MAP not found");
                return;
            }
        };
        let mut trust_map = match LruHashMap::<_, IpKey, TrustEntry>::try_from(m) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("failed to open TRUST_MAP: {}", e);
                return;
            }
        };
        let entry = TrustEntry {
            trust_score: trust_score.min(1000),
            pass_count: 0,
            drop_count: 0,
            last_update_ns: crate::time::monotonic_ns(),
            level: 0,
            padding: [0; 3],
        };
        let _ = trust_map.insert(key, entry, 0);
    }

    /// 解封由 Hub 下发且已被 Hub 删除的 IP，避免误删本地策略。
    pub async fn unblock_hub_policies(&self, ips: &[IpKey]) -> anyhow::Result<usize> {
        let store = match &self.store {
            Some(s) => s,
            None => return Ok(0),
        };

        let rows = store.load_blacklist().await?;
        let hub_set: HashSet<IpKey> = rows
            .into_iter()
            .filter(|(_, _, _, _, origin)| *origin == crate::config::BlockOrigin::Hub)
            .map(|(key, _, _, _, _)| key)
            .collect();

        let mut unblocked = 0usize;
        for ip in ips {
            if hub_set.contains(ip) {
                self.unblock_ip_key(*ip, "hub").await?;
                unblocked += 1;
            }
        }
        Ok(unblocked)
    }

    /// 应用从 Hub 统一下发的规则包（ACL / L7 / 防护项目）。
    pub async fn apply_hub_rules(
        &self,
        bundle: &crate::hub_client::RuleBundle,
    ) -> anyhow::Result<()> {
        self.set_port_acl(bundle.port_acl.clone()).await?;
        self.set_l7_patterns(bundle.l7_patterns.clone()).await?;
        self.set_protection_projects(bundle.protection_projects.clone())
            .await?;
        self.audit(
            "hub",
            AuditAction::PatchConfig,
            serde_json::json!({ "source": "hub_rules" }),
        )
        .await;
        Ok(())
    }

    /// 返回用于 Hub 心跳的运行时统计摘要 JSON。
    pub async fn stats_snapshot_json(&self) -> serde_json::Value {
        let rt = self.runtime.read().await.clone();
        serde_json::json!({
            "interface": rt.interface,
            "rate_limit_enabled": rt.rate_limit_enabled,
            "adaptive_enabled": rt.adaptive.enabled,
            "trust_enabled": rt.trust_enabled,
            "danger_level": rt.danger_level,
        })
    }

    async fn audit(
        &self,
        actor: impl Into<String>,
        action: AuditAction,
        detail: serde_json::Value,
    ) {
        if let Some(auditor) = &self.auditor {
            auditor.log(actor, action, detail, None).await;
        }
    }
}

impl RuntimeConfigSnapshot {
    fn from_config(config: &Config) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            interface: config.interface.clone(),
            web_port: config.web_port,
            web_bind: config.web_bind.clone(),
            log_level: config.log_level.clone(),
            log_json: config.log_json,
            store_path: config.store_path.clone(),
            alert_webhook_url: config.alert_webhook_url.clone(),
            alert_threshold_dps: config.alert_threshold_dps,
            alert_cooldown_s: config.alert_cooldown_s,
            rate_limit_enabled: config.rate_limit.enabled,
            syn_proxy_enabled: config.syn_proxy.enabled,
            l7_scan_enabled: config.l7_scan.enabled,
            ebpf_debug_enabled: config.ebpf_log_enabled,
            udp_flood_enabled: config.udp_flood_enabled,
            icmp_flood_enabled: config.icmp_flood_enabled,
            geoip_enabled: config.geoip.enabled,
            tcp_reset_on_drop: config.tcp_reset_on_drop,
            trust_enabled: config.trust_score.enabled,
            danger_level: 0,
            adaptive: config.adaptive.clone(),
            rate_limit: RateLimitParams {
                enabled: config.rate_limit.enabled,
                threshold: config.rate_limit.threshold,
                tick_ms: config.rate_limit.tick_ms,
                decay_num: config.rate_limit.decay_num,
                decay_den: config.rate_limit.decay_den,
                block_duration_s: config.rate_limit.block_duration_s,
            },
            port_acl: config.port_acl.clone(),
            protection_projects: config.protection_projects.clone(),
            l7_scan: config.l7_scan.clone(),
            geoip: config.geoip.clone(),
            threat_intel_feeds: config.threat_intel.feeds.clone(),
            whitelist_entries: config.whitelist.clone(),
            blacklist_entries: config.blacklist.clone(),
            hub_enabled: config.hub.enabled,
            hub_node_name: config.hub.node_name.clone(),
            hub_urls: config.hub.urls.clone(),
            packet_log_enabled: config.packet_log.enabled,
            packet_log_sample_rate: config.packet_log.sample_rate,
        }
    }
}

fn init_config_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut config_array: Array<_, RuntimeConfig> = ebpf
        .map_mut("CONFIG")
        .context("CONFIG map not found")?
        .try_into()?;
    let runtime = RuntimeConfig {
        rate_limit_enabled: u8::from(config.rate_limit.enabled),
        syn_proxy_enabled: u8::from(config.syn_proxy.enabled),
        l7_scan_enabled: u8::from(config.l7_scan.enabled),
        ebpf_debug: u8::from(config.ebpf_log_enabled),
        udp_flood_enabled: u8::from(config.udp_flood_enabled),
        icmp_flood_enabled: u8::from(config.icmp_flood_enabled),
        geoip_enabled: u8::from(config.geoip.enabled),
        tcp_reset_on_drop: u8::from(config.tcp_reset_on_drop),
        trust_enabled: u8::from(config.trust_score.enabled),
        danger_level: 0,
        packet_log_enabled: u8::from(config.packet_log.enabled),
        packet_log_sample_rate: config.packet_log.sample_rate,
        padding: [0; 3],
    };
    tracing::info!(
        "init_config_map: tcp_reset_on_drop={} ebpf_debug={}",
        runtime.tcp_reset_on_drop,
        runtime.ebpf_debug
    );
    config_array.set(0, runtime, 0)?;
    Ok(())
}

fn init_rate_limit_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut rate_cfg: Array<_, RateLimitConfig> = ebpf
        .map_mut("RATE_LIMIT_CFG")
        .context("RATE_LIMIT_CFG map not found")?
        .try_into()?;
    rate_cfg.set(
        0,
        RateLimitConfig {
            threshold: config.rate_limit.threshold,
            tick_ms: config.rate_limit.tick_ms,
            decay_num: config.rate_limit.decay_num,
            decay_den: config.rate_limit.decay_den,
            block_duration_s: config.rate_limit.block_duration_s,
        },
        0,
    )?;
    Ok(())
}

fn init_l7_patterns_map(
    ebpf: &mut Ebpf,
    pattern_cfgs: &[crate::config::L7PatternConfig],
) -> anyhow::Result<()> {
    let mut patterns: Array<_, L7Pattern> = ebpf
        .map_mut("L7_PATTERNS")
        .context("L7_PATTERNS map not found")?
        .try_into()?;

    // 先清空旧模式
    for i in 0..16u32 {
        let _ = patterns.set(i, eshield_common::L7Pattern::default(), 0);
    }

    for (i, pat_cfg) in pattern_cfgs.iter().enumerate().take(16) {
        let pattern_bytes = pat_cfg.pattern.as_bytes();
        if pattern_bytes.len() > 8 {
            anyhow::bail!("L7 pattern {} exceeds 8 bytes", i);
        }

        let mut sig = [0u8; 8];
        let mut mask = [0u8; 8];

        if let Some(mask_str) = &pat_cfg.mask {
            let mask_bytes = mask_str.as_bytes();
            if mask_bytes.len() != pattern_bytes.len() {
                anyhow::bail!("L7 pattern {} mask length mismatch", i);
            }
            sig[..pattern_bytes.len()].copy_from_slice(pattern_bytes);
            mask[..mask_bytes.len()].copy_from_slice(mask_bytes);
        } else {
            sig[..pattern_bytes.len()].copy_from_slice(pattern_bytes);
            mask[..pattern_bytes.len()].fill(0xff);
        }

        patterns.set(
            i as u32,
            eshield_common::L7Pattern {
                signature: u64::from_le_bytes(sig),
                mask: u64::from_le_bytes(mask),
                length: pattern_bytes.len() as u8,
                action: 0, // DROP
            },
            0,
        )?;
    }

    Ok(())
}

fn init_port_acl_map(ebpf: &mut Ebpf, items: &[PortAclItem]) -> anyhow::Result<()> {
    let mut port_acl: Array<_, PortAclEntry> = ebpf
        .map_mut("PORT_ACL")
        .context("PORT_ACL map not found")?
        .try_into()?;

    // 清空全部 128 个槽位
    for i in 0..128u32 {
        let _ = port_acl.set(i, PortAclEntry::default(), 0);
    }

    for (i, item) in items.iter().enumerate() {
        if i >= 128 {
            anyhow::bail!("too many port_acl entries (max 128)");
        }
        let entry = item
            .to_entry()
            .with_context(|| format!("invalid port_acl entry {}", i))?;
        port_acl.set(i as u32, entry, 0)?;
    }

    Ok(())
}

fn init_protection_projects_map(
    _ebpf: &mut Ebpf,
    projects: &[ProtectionProject],
) -> anyhow::Result<()> {
    // 当前 eBPF 栈空间有限，项目策略未在 eBPF 侧实时匹配；
    // 配置仍由控制面持久化并展示在 Dashboard，后续可启用内核态下发。
    if !projects.is_empty() {
        tracing::info!(
            "protection_projects loaded (userspace-only): count={}",
            projects.len()
        );
    }
    Ok(())
}

async fn apply_whitelist_map(
    ebpf: &mut Ebpf,
    config: &Config,
    current: &mut Vec<(IpKey, u32)>,
) -> anyhow::Result<()> {
    let new: HashSet<(IpKey, u32)> = config
        .whitelist
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .collect();

    // 先分别收集 v4 / v6 的删除与新增项，避免同时借用两个 map
    let mut remove_v4 = Vec::new();
    let mut remove_v6 = Vec::new();
    for (key, prefix) in current.iter().copied() {
        if !new.contains(&(key, prefix)) {
            match key.family() {
                Some(IpFamily::Ipv4) => remove_v4.push((key.ipv4(), prefix)),
                Some(IpFamily::Ipv6) => remove_v6.push((key.addr, prefix)),
                _ => {}
            }
            info!(
                "removed whitelist entry: {}/{}",
                format_ip_key(&key),
                prefix
            );
        }
    }

    let mut add_v4 = Vec::new();
    let mut add_v6 = Vec::new();
    for (addr, prefix) in &new {
        if !current.contains(&(*addr, *prefix)) {
            match addr.family() {
                Some(IpFamily::Ipv4) => add_v4.push((addr.ipv4(), *prefix)),
                Some(IpFamily::Ipv6) => add_v6.push((addr.addr, *prefix)),
                _ => {}
            }
            info!("added whitelist entry: {}/{}", format_ip_key(addr), prefix);
        }
    }

    {
        let mut whitelist_v4: LpmTrie<_, WhitelistKeyV4, u8> = ebpf
            .map_mut("WHITELIST_V4")
            .context("WHITELIST_V4 map not found")?
            .try_into()?;
        for (addr, prefix) in remove_v4 {
            whitelist_v4.remove(&LpmKey::new(prefix, WhitelistKeyV4 { addr: addr.to_be() }))?;
        }
        for (addr, prefix) in add_v4 {
            whitelist_v4.insert(
                &LpmKey::new(prefix, WhitelistKeyV4 { addr: addr.to_be() }),
                1,
                0,
            )?;
        }
    }

    {
        let mut whitelist_v6: LpmTrie<_, WhitelistKeyV6, u8> = ebpf
            .map_mut("WHITELIST_V6")
            .context("WHITELIST_V6 map not found")?
            .try_into()?;
        for (addr, prefix) in remove_v6 {
            whitelist_v6.remove(&LpmKey::new(prefix, WhitelistKeyV6 { addr }))?;
        }
        for (addr, prefix) in add_v6 {
            whitelist_v6.insert(&LpmKey::new(prefix, WhitelistKeyV6 { addr }), 1, 0)?;
        }
    }

    current.clear();
    current.extend(new);
    Ok(())
}

async fn apply_blacklist_map(
    ebpf: &mut Ebpf,
    config: &Config,
    current: &mut Vec<IpKey>,
) -> anyhow::Result<()> {
    let mut blacklist: LruHashMap<_, IpKey, BlockEntry> = ebpf
        .map_mut("BLACKLIST")
        .context("BLACKLIST map not found")?
        .try_into()?;

    let new: HashSet<IpKey> = config
        .blacklist
        .iter()
        .map(|s| parse_ip_or_cidr(s))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .collect();

    // 仅移除由配置文件加入的静态黑名单（reason == BLACKLIST），保留 API / 自适应封禁
    for key in current.iter() {
        if !new.contains(key) {
            if let Ok(entry) = blacklist.get(key, 0) {
                if entry.block_reason == rules::BLACKLIST as u8 {
                    blacklist.remove(key)?;
                    info!("removed static blacklist entry: {}", format_ip_key(key));
                }
            }
        }
    }

    for key in &new {
        if !current.contains(key) {
            let entry = BlockEntry {
                blocked_until_ns: BLOCK_PERMANENT,
                block_reason: rules::BLACKLIST as u8,
                hit_count: 0,
                first_seen_ns: 0,
            };
            blacklist.insert(*key, entry, 0)?;
            info!("added static blacklist entry: {}", format_ip_key(key));
        }
    }

    current.clear();
    current.extend(new);
    Ok(())
}

async fn apply_geoip_map(
    ebpf: &mut Ebpf,
    config: &Config,
    current: &mut Vec<(IpKey, u32)>,
) -> anyhow::Result<()> {
    // 先分类旧条目，避免同时借用两个 map。
    let mut old_v4 = Vec::new();
    let mut old_v6 = Vec::new();
    for (key, prefix) in current.drain(..) {
        match key.family() {
            Some(IpFamily::Ipv4) => old_v4.push((key.ipv4(), prefix)),
            Some(IpFamily::Ipv6) => old_v6.push((key.addr, prefix)),
            _ => {}
        }
    }

    // 清空旧规则
    {
        let mut geoip_v4: LpmTrie<_, GeoIpKeyV4, u8> = ebpf
            .map_mut("GEOIP_BLOCKED_V4")
            .context("GEOIP_BLOCKED_V4 map not found")?
            .try_into()?;
        for (addr, prefix) in old_v4 {
            geoip_v4.remove(&LpmKey::new(prefix, GeoIpKeyV4 { addr: addr.to_be() }))?;
        }
    }
    {
        let mut geoip_v6: LpmTrie<_, GeoIpKeyV6, u8> = ebpf
            .map_mut("GEOIP_BLOCKED_V6")
            .context("GEOIP_BLOCKED_V6 map not found")?
            .try_into()?;
        for (addr, prefix) in old_v6 {
            geoip_v6.remove(&LpmKey::new(prefix, GeoIpKeyV6 { addr }))?;
        }
    }

    if !config.geoip.enabled {
        return Ok(());
    }

    let blocks = crate::geoip::load_geoip_blocks(&config.geoip)?;
    if blocks.is_empty() {
        return Ok(());
    }

    // 分类新条目
    let mut new_v4 = Vec::new();
    let mut new_v6 = Vec::new();
    for block in blocks {
        match block.key.family() {
            Some(IpFamily::Ipv4) => new_v4.push((block.key.ipv4(), block.prefix)),
            Some(IpFamily::Ipv6) => new_v6.push((block.key.addr, block.prefix)),
            _ => continue,
        }
        info!(
            "added GeoIP block: {}/{} {}",
            format_ip_key(&block.key),
            block.prefix,
            block.reason
        );
        current.push((block.key, block.prefix));
    }

    {
        let mut geoip_v4: LpmTrie<_, GeoIpKeyV4, u8> = ebpf
            .map_mut("GEOIP_BLOCKED_V4")
            .context("GEOIP_BLOCKED_V4 map not found")?
            .try_into()?;
        for (addr, prefix) in new_v4 {
            geoip_v4.insert(
                &LpmKey::new(prefix, GeoIpKeyV4 { addr: addr.to_be() }),
                1,
                0,
            )?;
        }
    }
    {
        let mut geoip_v6: LpmTrie<_, GeoIpKeyV6, u8> = ebpf
            .map_mut("GEOIP_BLOCKED_V6")
            .context("GEOIP_BLOCKED_V6 map not found")?
            .try_into()?;
        for (addr, prefix) in new_v6 {
            geoip_v6.insert(&LpmKey::new(prefix, GeoIpKeyV6 { addr }), 1, 0)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::parse_ip;
    use eshield_common::IpFamily;

    #[test]
    fn test_parse_ip_ipv4_ok() {
        let key = parse_ip("192.0.2.1").unwrap();
        assert_eq!(key.family, IpFamily::Ipv4 as u8);
        assert_eq!(key.ipv4(), 0xc000_0201);
    }

    #[test]
    fn test_parse_ip_ipv6_ok() {
        let key = parse_ip("::1").unwrap();
        assert_eq!(key.family, IpFamily::Ipv6 as u8);
    }

    #[test]
    fn test_parse_cidr_ok() {
        let (key, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(key.family, IpFamily::Ipv4 as u8);
        assert_eq!(key.ipv4(), 0x0a00_0000);
        assert_eq!(prefix, 8);
    }

    #[test]
    fn test_parse_cidr_ipv6_ok() {
        let (key, prefix) = parse_cidr("2001:db8::/32").unwrap();
        assert_eq!(key.family, IpFamily::Ipv6 as u8);
        assert_eq!(prefix, 32);
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_rejected() {
        assert!(parse_cidr("192.0.2.0/33").is_err());
        assert!(parse_cidr("2001:db8::/129").is_err());
    }

    #[test]
    fn test_runtime_snapshot_from_config_preserves_ebpf_debug() {
        let mut config = Config {
            interface: "lo".to_string(),
            ebpf_log_enabled: true,
            ..Config::default()
        };
        config.rate_limit.enabled = true;
        config.rate_limit.threshold = 100;

        let snapshot = RuntimeConfigSnapshot::from_config(&config);
        assert!(snapshot.ebpf_debug_enabled);
        assert!(snapshot.rate_limit_enabled);
        assert_eq!(snapshot.rate_limit.threshold, 100);
    }
}

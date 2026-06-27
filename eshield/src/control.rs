use anyhow::Context;
use aya::{
    maps::{lpm_trie::Key as LpmKey, Array, HashMap as LruHashMap, LpmTrie},
    Ebpf,
};
use eshield_common::{
    rules, BlockEntry, GeoIpKeyV4, GeoIpKeyV6, IpFamily, IpKey, L7Pattern, PortAclEntry,
    RateLimitConfig, RuntimeConfig, WafRule, WhitelistKeyV4, WhitelistKeyV6,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

use crate::audit::{AuditAction, Auditor};
use crate::config::Config;
use crate::ip::{format_ip_key, parse_cidr, parse_ip, parse_ip_or_cidr};
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
}

/// 运行时可读快照（用于 Web / CLI 展示）。
#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeConfigSnapshot {
    pub rate_limit_enabled: bool,
    pub syn_proxy_enabled: bool,
    pub l7_scan_enabled: bool,
    pub ebpf_debug_enabled: bool,
    pub udp_flood_enabled: bool,
    pub icmp_flood_enabled: bool,
    pub waf_enabled: bool,
    pub challenge_enabled: bool,
    pub geoip_enabled: bool,
    pub rate_limit: RateLimitParams,
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
    pub waf_enabled: Option<bool>,
    pub challenge_enabled: Option<bool>,
    pub geoip_enabled: Option<bool>,
    pub rate_limit: Option<RateLimitParams>,
}

impl ControlState {
    pub async fn new(
        ebpf: Arc<Mutex<Ebpf>>,
        config_path: String,
        config: &Config,
        auditor: Option<Auditor>,
        store: Option<RuleStore>,
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
        };

        // 初始化运行时配置与策略
        {
            let mut guard = state.ebpf.lock().await;
            init_config_map(&mut guard, config)?;
            init_rate_limit_map(&mut guard, config)?;
            init_l7_patterns_map(&mut guard, config)?;
            init_port_acl_map(&mut guard, config)?;
            init_waf_rules_map(&mut guard, config)?;
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
        init_l7_patterns_map(&mut guard, &config)?;
        init_port_acl_map(&mut guard, &config)?;
        init_waf_rules_map(&mut guard, &config)?;
        apply_whitelist_map(&mut guard, &config, &mut whitelist).await?;
        apply_blacklist_map(&mut guard, &config, &mut blacklist).await?;
        apply_geoip_map(&mut guard, &config, &mut geoip_blocks).await?;

        *self.runtime.write().await = RuntimeConfigSnapshot::from_config(&config);
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
        self.block_ip_raw(key, duration_s).await?;

        if let Some(store) = &self.store {
            let now_ns = now_ns();
            let blocked_until_ns = if duration_s == 0 {
                0
            } else {
                let block_ns = duration_s.saturating_mul(1_000_000_000);
                now_ns.saturating_add(block_ns)
            };
            store
                .save_blacklist(key, blocked_until_ns, rules::API_BLOCK as u8, now_ns)
                .await?;
        }

        self.audit(
            "api",
            AuditAction::BlockIp,
            serde_json::json!({ "ip": ip_str, "duration_s": duration_s }),
        )
        .await;
        info!("API block: {} duration={}s", ip_str, duration_s);
        Ok(())
    }

    async fn block_ip_raw(&self, key: IpKey, duration_s: u64) -> anyhow::Result<()> {
        let mut guard = self.ebpf.lock().await;
        let mut blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
            .map_mut("BLACKLIST")
            .context("BLACKLIST map not found")?
            .try_into()?;

        let blocked_until_ns = if duration_s == 0 {
            0
        } else {
            let now_ns = now_ns();
            let block_ns = duration_s.saturating_mul(1_000_000_000);
            now_ns.saturating_add(block_ns)
        };

        blacklist.insert(
            key,
            BlockEntry {
                blocked_until_ns,
                block_reason: rules::API_BLOCK as u8,
                hit_count: 0,
                first_seen_ns: now_ns(),
            },
            0,
        )?;
        Ok(())
    }

    /// 实时解封某个 IP。
    pub async fn unblock_ip(&self, ip_str: &str) -> anyhow::Result<()> {
        let key = parse_ip_or_cidr(ip_str)?;
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
            "api",
            AuditAction::UnblockIp,
            serde_json::json!({ "ip": ip_str }),
        )
        .await;
        info!("API unblock: {}", ip_str);
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

    async fn allow_cidr_raw(&self, key: IpKey, prefix: u32) -> anyhow::Result<()> {
        let mut guard = self.ebpf.lock().await;

        match key.family() {
            Some(IpFamily::Ipv4) => {
                let mut whitelist: LpmTrie<_, WhitelistKeyV4, u8> = guard
                    .map_mut("WHITELIST_V4")
                    .context("WHITELIST_V4 map not found")?
                    .try_into()?;
                whitelist.insert(
                    &LpmKey::new(prefix, WhitelistKeyV4 { addr: key.ipv4().to_be() }),
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
                whitelist.remove(&LpmKey::new(prefix, WhitelistKeyV4 { addr: key.ipv4().to_be() }))?;
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
        if let Some(enabled) = patch.waf_enabled {
            snapshot.waf_enabled = enabled;
        }
        if let Some(enabled) = patch.challenge_enabled {
            snapshot.challenge_enabled = enabled;
        }
        if let Some(enabled) = patch.geoip_enabled {
            snapshot.geoip_enabled = enabled;
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
                    waf_enabled: u8::from(snapshot.waf_enabled),
                    challenge_enabled: u8::from(snapshot.challenge_enabled),
                    geoip_enabled: u8::from(snapshot.geoip_enabled),
                    padding: [0; 7],
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

    /// 从持久化存储加载动态规则并应用（不记录审计，避免启动/重载时产生大量日志）。
    pub async fn load_persisted_rules(&self) -> anyhow::Result<()> {
        let Some(store) = &self.store else { return Ok(()) };

        let now_ns = now_ns();
        for (key, blocked_until_ns, _reason, _first_seen_ns) in store.load_blacklist().await? {
            // 已过期则跳过
            if blocked_until_ns != 0 && blocked_until_ns <= now_ns {
                continue;
            }
            let duration_s = if blocked_until_ns == 0 {
                0
            } else {
                blocked_until_ns.saturating_sub(now_ns) / 1_000_000_000
            };
            self.block_ip_raw(key, duration_s).await?;
        }

        for (key, prefix) in store.load_whitelist().await? {
            self.allow_cidr_raw(key, prefix).await?;
        }

        Ok(())
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
            rate_limit_enabled: config.rate_limit.enabled,
            syn_proxy_enabled: config.syn_proxy.enabled,
            l7_scan_enabled: config.l7_scan.enabled,
            ebpf_debug_enabled: config.ebpf_log_enabled,
            udp_flood_enabled: config.udp_flood_enabled,
            icmp_flood_enabled: config.icmp_flood_enabled,
            waf_enabled: config.waf.enabled,
            challenge_enabled: config.challenge.enabled,
            geoip_enabled: config.geoip.enabled,
            rate_limit: RateLimitParams {
                enabled: config.rate_limit.enabled,
                threshold: config.rate_limit.threshold,
                tick_ms: config.rate_limit.tick_ms,
                decay_num: config.rate_limit.decay_num,
                decay_den: config.rate_limit.decay_den,
                block_duration_s: config.rate_limit.block_duration_s,
            },
        }
    }
}

fn init_config_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut config_array: Array<_, RuntimeConfig> = ebpf
        .map_mut("CONFIG")
        .context("CONFIG map not found")?
        .try_into()?;
    config_array.set(
        0,
        RuntimeConfig {
            rate_limit_enabled: u8::from(config.rate_limit.enabled),
            syn_proxy_enabled: u8::from(config.syn_proxy.enabled),
            l7_scan_enabled: u8::from(config.l7_scan.enabled),
            ebpf_debug: u8::from(config.ebpf_log_enabled),
            udp_flood_enabled: u8::from(config.udp_flood_enabled),
            icmp_flood_enabled: u8::from(config.icmp_flood_enabled),
            waf_enabled: u8::from(config.waf.enabled),
            challenge_enabled: u8::from(config.challenge.enabled),
            geoip_enabled: u8::from(config.geoip.enabled),
            padding: [0; 7],
        },
        0,
    )?;
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

fn init_l7_patterns_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut patterns: Array<_, L7Pattern> = ebpf
        .map_mut("L7_PATTERNS")
        .context("L7_PATTERNS map not found")?
        .try_into()?;

    // 先清空旧模式
    for i in 0..16u32 {
        let _ = patterns.set(i, eshield_common::L7Pattern::default(), 0);
    }

    for (i, pat_cfg) in config.l7_scan.patterns.iter().enumerate().take(16) {
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

fn init_port_acl_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut port_acl: Array<_, PortAclEntry> = ebpf
        .map_mut("PORT_ACL")
        .context("PORT_ACL map not found")?
        .try_into()?;

    // 清空全部 128 个槽位
    for i in 0..128u32 {
        let _ = port_acl.set(i, PortAclEntry::default(), 0);
    }

    for (i, item) in config.port_acl.iter().enumerate() {
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

fn init_waf_rules_map(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut waf_rules: Array<_, WafRule> = ebpf
        .map_mut("WAF_RULES")
        .context("WAF_RULES map not found")?
        .try_into()?;

    for i in 0..eshield_common::WAF_RULES_MAX as u32 {
        let _ = waf_rules.set(i, WafRule::default(), 0);
    }

    for (i, item) in config.waf.rules.iter().enumerate().take(eshield_common::WAF_RULES_MAX) {
        let rule = compile_waf_rule(item).with_context(|| format!("invalid waf rule {}", i))?;
        waf_rules.set(i as u32, rule, 0)?;
    }

    Ok(())
}

fn compile_waf_rule(item: &crate::config::WafRuleItem) -> anyhow::Result<WafRule> {
    use eshield_common::{waf_match, HttpMethod, WafAction};

    let action = match item.action.to_lowercase().as_str() {
        "drop" => WafAction::Drop as u8,
        "log" => WafAction::Log as u8,
        "challenge" => WafAction::Challenge as u8,
        other => anyhow::bail!("invalid waf action: {}", other),
    };

    let method = if let Some(m) = &item.r#match.method {
        match m.to_uppercase().as_str() {
            "GET" => HttpMethod::Get as u8,
            "POST" => HttpMethod::Post as u8,
            "PUT" => HttpMethod::Put as u8,
            "DELETE" => HttpMethod::Delete as u8,
            "HEAD" => HttpMethod::Head as u8,
            "OPTIONS" => HttpMethod::Options as u8,
            "PATCH" => HttpMethod::Patch as u8,
            "ANY" => HttpMethod::Any as u8,
            other => anyhow::bail!("invalid waf method: {}", other),
        }
    } else {
        HttpMethod::Any as u8
    };

    let mut match_flags = 0u8;

    fn sig_mask(src: &Option<String>) -> ([u8; eshield_common::WAF_FIELD_LEN], [u8; eshield_common::WAF_FIELD_LEN]) {
        let mut sig = [0u8; eshield_common::WAF_FIELD_LEN];
        let mut mask = [0u8; eshield_common::WAF_FIELD_LEN];
        if let Some(s) = src {
            let bytes = s.as_bytes();
            let len = bytes.len().min(eshield_common::WAF_FIELD_LEN);
            sig[..len].copy_from_slice(&bytes[..len]);
            for i in 0..len {
                mask[i] = 0xff;
            }
        }
        (sig, mask)
    }

    let (path_sig, path_mask) = sig_mask(&item.r#match.path_prefix);
    let (host_sig, host_mask) = sig_mask(&item.r#match.host);
    let (user_agent_sig, user_agent_mask) = sig_mask(&item.r#match.user_agent);
    let (body_sig, body_mask) = sig_mask(&item.r#match.body_prefix);

    if item.r#match.path_prefix.is_some() {
        match_flags |= waf_match::PATH_PREFIX;
    }
    if item.r#match.host.is_some() {
        match_flags |= waf_match::HOST;
    }
    if item.r#match.user_agent.is_some() {
        match_flags |= waf_match::USER_AGENT;
    }
    if item.r#match.body_prefix.is_some() {
        match_flags |= waf_match::BODY_PREFIX;
    }
    if item.r#match.method.is_some() {
        match_flags |= waf_match::METHOD;
    }

    Ok(WafRule {
        enabled: u8::from(item.enabled),
        priority: item.priority,
        action,
        method,
        match_flags,
        padding: [0; 3],
        path_sig,
        path_mask,
        host_sig,
        host_mask,
        user_agent_sig,
        user_agent_mask,
        body_sig,
        body_mask,
    })
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
            info!("removed whitelist entry: {}/{}", format_ip_key(&key), prefix);
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
            whitelist_v4.insert(&LpmKey::new(prefix, WhitelistKeyV4 { addr: addr.to_be() }), 1, 0)?;
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
            whitelist_v6.insert(&LpmKey::new(prefix, WhitelistKeyV6 { addr: addr }), 1, 0)?;
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
                blocked_until_ns: 0,
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
            geoip_v4.insert(&LpmKey::new(prefix, GeoIpKeyV4 { addr: addr.to_be() }), 1, 0)?;
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

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
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

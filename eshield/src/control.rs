use anyhow::Context;
use aya::{
    maps::{lpm_trie::Key as LpmKey, Array, HashMap as LruHashMap, LpmTrie},
    Ebpf,
};
use eshield_common::{rules, BlockEntry, L7Pattern, RateLimitConfig, RuntimeConfig, WhitelistKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

use crate::config::Config;

/// 控制面共享状态，Web / CLI / SIGHUP 都通过它操作 eBPF Maps。
pub struct ControlState {
    pub ebpf: Arc<Mutex<Ebpf>>,
    pub config_path: String,
    pub runtime: RwLock<RuntimeConfigSnapshot>,
    pub whitelist: Mutex<Vec<(u32, u32)>>,
    pub blacklist: Mutex<Vec<u32>>,
}

/// 运行时可读快照（用于 Web / CLI 展示）。
#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeConfigSnapshot {
    pub rate_limit_enabled: bool,
    pub syn_proxy_enabled: bool,
    pub l7_scan_enabled: bool,
    pub ebpf_debug_enabled: bool,
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

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuntimeConfigPatch {
    pub rate_limit_enabled: Option<bool>,
    pub syn_proxy_enabled: Option<bool>,
    pub l7_scan_enabled: Option<bool>,
    pub ebpf_debug_enabled: Option<bool>,
    pub rate_limit: Option<RateLimitParams>,
}

impl ControlState {
    pub async fn new(
        ebpf: Arc<Mutex<Ebpf>>,
        config_path: String,
        config: &Config,
    ) -> anyhow::Result<Self> {
        let state = Self {
            ebpf,
            config_path,
            runtime: RwLock::new(RuntimeConfigSnapshot::from_config(config)),
            whitelist: Mutex::new(Vec::new()),
            blacklist: Mutex::new(Vec::new()),
        };

        // 初始化运行时配置与策略
        {
            let mut guard = state.ebpf.lock().await;
            init_config_map(&mut guard, config)?;
            init_rate_limit_map(&mut guard, config)?;
            init_l7_patterns_map(&mut guard, config)?;
            let mut blacklist = state.blacklist.lock().await;
            let mut whitelist = state.whitelist.lock().await;
            apply_blacklist_map(&mut guard, config, &mut blacklist).await?;
            apply_whitelist_map(&mut guard, config, &mut whitelist).await?;
        }

        Ok(state)
    }

    /// 从配置文件重新加载全部策略。
    pub async fn reload_config_file(&self) -> anyhow::Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let mut guard = self.ebpf.lock().await;
        let mut whitelist = self.whitelist.lock().await;
        let mut blacklist = self.blacklist.lock().await;

        init_config_map(&mut guard, &config)?;
        init_rate_limit_map(&mut guard, &config)?;
        init_l7_patterns_map(&mut guard, &config)?;
        apply_whitelist_map(&mut guard, &config, &mut whitelist).await?;
        apply_blacklist_map(&mut guard, &config, &mut blacklist).await?;

        *self.runtime.write().await = RuntimeConfigSnapshot::from_config(&config);
        Ok(())
    }

    /// 实时封禁某个 IP（API 控制）。
    pub async fn block_ip(&self, ip_str: &str, duration_s: u64) -> anyhow::Result<()> {
        let ip = parse_ip(ip_str)?;
        let mut guard = self.ebpf.lock().await;
        let mut blacklist: LruHashMap<_, u32, BlockEntry> = guard
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
            ip,
            BlockEntry {
                blocked_until_ns,
                block_reason: rules::API_BLOCK as u8,
                hit_count: 0,
                first_seen_ns: now_ns(),
            },
            0,
        )?;

        self.blacklist.lock().await.push(ip);
        info!("API block: {} duration={}s", ip_str, duration_s);
        Ok(())
    }

    /// 实时解封某个 IP。
    pub async fn unblock_ip(&self, ip_str: &str) -> anyhow::Result<()> {
        let ip = parse_ip(ip_str)?;
        let mut guard = self.ebpf.lock().await;
        let mut blacklist: LruHashMap<_, u32, BlockEntry> = guard
            .map_mut("BLACKLIST")
            .context("BLACKLIST map not found")?
            .try_into()?;
        blacklist.remove(&ip)?;

        self.blacklist.lock().await.retain(|&x| x != ip);
        info!("API unblock: {}", ip_str);
        Ok(())
    }

    /// 实时放行某个 CIDR。
    pub async fn allow_cidr(&self, cidr: &str) -> anyhow::Result<()> {
        let (addr, prefix) = parse_cidr(cidr)?;
        let mut guard = self.ebpf.lock().await;
        let mut whitelist: LpmTrie<_, WhitelistKey, u8> = guard
            .map_mut("WHITELIST")
            .context("WHITELIST map not found")?
            .try_into()?;
        whitelist.insert(&LpmKey::new(prefix, WhitelistKey { addr }), 1, 0)?;

        self.whitelist.lock().await.push((addr, prefix));
        info!("API whitelist add: {}", cidr);
        Ok(())
    }

    /// 实时移除某个 CIDR 放行。
    pub async fn disallow_cidr(&self, cidr: &str) -> anyhow::Result<()> {
        let (addr, prefix) = parse_cidr(cidr)?;
        let mut guard = self.ebpf.lock().await;
        let mut whitelist: LpmTrie<_, WhitelistKey, u8> = guard
            .map_mut("WHITELIST")
            .context("WHITELIST map not found")?
            .try_into()?;
        whitelist.remove(&LpmKey::new(prefix, WhitelistKey { addr }))?;

        self.whitelist.lock().await.retain(|&x| x != (addr, prefix));
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

        let mut guard = self.ebpf.lock().await;

        if let Some(rl) = patch.rate_limit {
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
                    padding: [0; 4],
                },
                0,
            )?;
        }

        *self.runtime.write().await = snapshot;
        Ok(())
    }
}

impl RuntimeConfigSnapshot {
    fn from_config(config: &Config) -> Self {
        Self {
            rate_limit_enabled: config.rate_limit.enabled,
            syn_proxy_enabled: config.syn_proxy.enabled,
            l7_scan_enabled: config.l7_scan.enabled,
            ebpf_debug_enabled: config.ebpf_log_enabled,
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
            padding: [0; 4],
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

async fn apply_whitelist_map(
    ebpf: &mut Ebpf,
    config: &Config,
    current: &mut Vec<(u32, u32)>,
) -> anyhow::Result<()> {
    let mut whitelist: LpmTrie<_, WhitelistKey, u8> = ebpf
        .map_mut("WHITELIST")
        .context("WHITELIST map not found")?
        .try_into()?;

    let new: HashSet<(u32, u32)> = config
        .whitelist
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .collect();

    for key in current.iter().copied() {
        if !new.contains(&key) {
            whitelist.remove(&LpmKey::new(key.1, WhitelistKey { addr: key.0 }))?;
            info!("removed whitelist entry: {}/{}", format_addr(key.0), key.1);
        }
    }

    for (addr, prefix) in &new {
        if !current.contains(&(*addr, *prefix)) {
            whitelist.insert(&LpmKey::new(*prefix, WhitelistKey { addr: *addr }), 1, 0)?;
            info!("added whitelist entry: {}/{}", format_addr(*addr), prefix);
        }
    }

    current.clear();
    current.extend(new);
    Ok(())
}

async fn apply_blacklist_map(
    ebpf: &mut Ebpf,
    config: &Config,
    current: &mut Vec<u32>,
) -> anyhow::Result<()> {
    let mut blacklist: LruHashMap<_, u32, BlockEntry> = ebpf
        .map_mut("BLACKLIST")
        .context("BLACKLIST map not found")?
        .try_into()?;

    let new: HashSet<u32> = config
        .blacklist
        .iter()
        .map(|s| parse_ip(s))
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .collect();

    // 仅移除由配置文件加入的静态黑名单（reason == BLACKLIST），保留 API / 自适应封禁
    for ip in current.iter().copied() {
        if !new.contains(&ip) {
            if let Ok(entry) = blacklist.get(&ip, 0) {
                if entry.block_reason == rules::BLACKLIST as u8 {
                    blacklist.remove(&ip)?;
                    info!("removed static blacklist entry: {}", format_addr(ip));
                }
            }
        }
    }

    for ip in &new {
        if !current.contains(ip) {
            let entry = BlockEntry {
                blocked_until_ns: 0,
                block_reason: rules::BLACKLIST as u8,
                hit_count: 0,
                first_seen_ns: 0,
            };
            blacklist.insert(*ip, entry, 0)?;
            info!("added static blacklist entry: {}", format_addr(*ip));
        }
    }

    current.clear();
    current.extend(new);
    Ok(())
}

pub fn parse_ip(s: &str) -> anyhow::Result<u32> {
    let addr: IpAddr = s.parse().context("invalid IP address")?;
    match addr {
        IpAddr::V4(v4) => Ok(u32::from_be_bytes(v4.octets())),
        IpAddr::V6(_) => anyhow::bail!("IPv6 is not supported yet"),
    }
}

pub fn parse_cidr(s: &str) -> anyhow::Result<(u32, u32)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid CIDR: {}", s);
    }
    let addr: IpAddr = parts[0].parse().context("invalid IP address")?;
    let prefix: u32 = parts[1].parse().context("invalid prefix length")?;
    if prefix > 32 {
        anyhow::bail!("invalid prefix length: {}", prefix);
    }

    match addr {
        IpAddr::V4(v4) => {
            let addr = u32::from_be_bytes(v4.octets());
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok((addr & mask, prefix))
        }
        IpAddr::V6(_) => anyhow::bail!("IPv6 is not supported yet"),
    }
}

pub fn format_addr(addr: u32) -> String {
    Ipv4Addr::from(addr.to_be_bytes()).to_string()
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

    #[test]
    fn test_parse_ip_ipv4_ok() {
        assert_eq!(parse_ip("192.0.2.1").unwrap(), 0xc000_0201);
    }

    #[test]
    fn test_parse_ip_ipv6_rejected() {
        assert!(parse_ip("::1").is_err());
    }

    #[test]
    fn test_parse_cidr_ok() {
        let (addr, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(addr, 0x0a00_0000);
        assert_eq!(prefix, 8);
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_rejected() {
        assert!(parse_cidr("192.0.2.0/33").is_err());
    }

    #[test]
    fn test_format_addr() {
        assert_eq!(format_addr(0xc000_0201), "192.0.2.1");
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

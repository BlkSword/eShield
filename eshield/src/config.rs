use anyhow::Context;
use eshield_common::{IpKey, PortAclEntry};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// 黑名单条目的来源，用于区分本地生成与 Hub 下发，避免策略回环。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOrigin {
    Local,
    #[default]
    Api,
    Adaptive,
    ThreatIntel,
    Hub,
}

impl BlockOrigin {
    /// 是否允许向 Hub 上报该来源的策略。
    pub fn publishable(&self) -> bool {
        matches!(
            self,
            BlockOrigin::Local
                | BlockOrigin::Api
                | BlockOrigin::Adaptive
                | BlockOrigin::ThreatIntel
        )
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    pub interface: String,
    #[allow(dead_code)]
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    #[serde(default)]
    pub log_level: String,
    #[serde(default = "default_false")]
    pub ebpf_log_enabled: bool,
    #[serde(default = "default_false")]
    pub udp_flood_enabled: bool,
    #[serde(default = "default_false")]
    pub icmp_flood_enabled: bool,
    #[serde(default = "default_false")]
    pub tcp_reset_on_drop: bool,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub port_rate_limit: PortRateLimitConfig,
    #[serde(default)]
    pub syn_proxy: SynProxyConfig,
    #[serde(default)]
    pub l7_scan: L7ScanConfig,
    #[serde(default)]
    pub adaptive: AdaptiveConfig,
    #[serde(default)]
    pub port_acl: Vec<PortAclItem>,
    #[serde(default)]
    pub protection_projects: Vec<ProtectionProject>,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    #[serde(default)]
    pub web_bind: Option<String>,
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default = "default_false")]
    pub log_json: bool,
    #[serde(default = "default_store_path")]
    pub store_path: String,
    #[serde(default = "default_timeseries_retention_days")]
    pub timeseries_retention_days: u64,
    #[serde(default)]
    pub alert_webhook_url: Option<String>,
    #[serde(default = "default_alert_webhook_type")]
    pub alert_webhook_type: String,
    #[serde(default = "default_alert_threshold_dps")]
    pub alert_threshold_dps: u64,
    #[serde(default = "default_alert_cooldown_s")]
    pub alert_cooldown_s: u64,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub trust_score: TrustScoreConfig,
    #[serde(default)]
    pub danger_signal: DangerSignalConfig,
    #[serde(default)]
    pub hub: HubConfig,
    #[serde(default)]
    pub packet_log: PacketLogConfig,
}

fn default_web_port() -> u16 {
    8720
}

fn default_store_path() -> String {
    "/var/lib/eshield/rules.redb".to_string()
}

fn default_timeseries_retention_days() -> u64 {
    30
}

fn default_alert_webhook_type() -> String {
    "generic".to_string()
}

fn default_alert_threshold_dps() -> u64 {
    1000
}

fn default_alert_cooldown_s() -> u64 {
    60
}

/// 审计日志持久化配置。
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_audit_path")]
    pub path: String,
    #[serde(default = "default_audit_max_size_mb")]
    pub max_size_mb: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_audit_path(),
            max_size_mb: default_audit_max_size_mb(),
        }
    }
}

fn default_audit_path() -> String {
    "/var/log/eshield/audit.log".to_string()
}

fn default_audit_max_size_mb() -> u64 {
    100
}

/// Trust Score 配置（v0.4.0）
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TrustScoreConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_trust_add_divisor")]
    pub add_divisor: u32,
    #[serde(default = "default_trust_sub_divisor")]
    pub sub_divisor: u32,
}

impl Default for TrustScoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            add_divisor: 100,
            sub_divisor: 3,
        }
    }
}
fn default_trust_add_divisor() -> u32 {
    100
}
fn default_trust_sub_divisor() -> u32 {
    3
}

/// Danger Signal 配置（v0.4.0）
#[derive(Debug, Clone, Deserialize)]
pub struct DangerSignalConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_danger_sample_s")]
    pub sample_interval_s: u64,
    #[serde(default = "default_danger_anomaly_multiplier")]
    pub anomaly_multiplier: f64,
}

impl Default for DangerSignalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_interval_s: 5,
            anomaly_multiplier: 2.0,
        }
    }
}
fn default_danger_sample_s() -> u64 {
    5
}
fn default_danger_anomaly_multiplier() -> f64 {
    2.0
}

/// Hub 分布式同步配置（v0.4.2）。
#[derive(Debug, Clone, Deserialize)]
pub struct HubConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_hub_pull_interval_s")]
    pub sync_pull_interval_s: u64,
    #[serde(default = "default_hub_push_interval_s")]
    pub sync_push_interval_s: u64,
    #[serde(default = "default_hub_push_min_hit_count")]
    pub push_min_hit_count: u32,
    #[serde(default = "default_hub_push_min_trust")]
    pub push_min_trust: u32,
    #[serde(default = "default_hub_push_max_batch_size")]
    pub push_max_batch_size: usize,
    #[serde(default = "default_false")]
    pub sync_rules_enabled: bool,
    #[serde(default = "default_hub_sync_rules_interval_s")]
    pub sync_rules_interval_s: u64,
    #[serde(default)]
    pub tls: HubTlsConfig,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            urls: Vec::new(),
            node_name: String::new(),
            token: String::new(),
            sync_pull_interval_s: default_hub_pull_interval_s(),
            sync_push_interval_s: default_hub_push_interval_s(),
            push_min_hit_count: default_hub_push_min_hit_count(),
            push_min_trust: default_hub_push_min_trust(),
            push_max_batch_size: default_hub_push_max_batch_size(),
            sync_rules_enabled: false,
            sync_rules_interval_s: default_hub_sync_rules_interval_s(),
            tls: HubTlsConfig::default(),
        }
    }
}

/// 采样包日志配置（v0.4.2）
#[derive(Debug, Clone, Deserialize)]
pub struct PacketLogConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_packet_log_sample_rate")]
    pub sample_rate: u16,
    #[serde(default = "default_packet_log_memory_max_entries")]
    pub memory_max_entries: usize,
    /// 是否在前端展示 payload 十六进制（当前默认开启，保留供后续细粒度控制）
    #[serde(default = "default_true")]
    #[allow(dead_code)]
    pub payload_hex: bool,
}

impl Default for PacketLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_rate: default_packet_log_sample_rate(),
            memory_max_entries: default_packet_log_memory_max_entries(),
            payload_hex: true,
        }
    }
}

fn default_packet_log_sample_rate() -> u16 {
    10000
}

fn default_packet_log_memory_max_entries() -> usize {
    50000
}

fn default_hub_pull_interval_s() -> u64 {
    10
}
fn default_hub_push_interval_s() -> u64 {
    5
}
fn default_hub_push_min_hit_count() -> u32 {
    10
}
fn default_hub_push_min_trust() -> u32 {
    100
}
fn default_hub_push_max_batch_size() -> usize {
    100
}
fn default_hub_sync_rules_interval_s() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct HubTlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    #[serde(default = "default_true")]
    pub verify: bool,
}

impl Default for HubTlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            verify: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAclItem {
    pub protocol: String,
    pub dport: String,
    pub action: String,
}

/// 防护项目：按协议 + 端口 + 可选目标 IP 绑定一组防御策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionProject {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub protocol: String,
    pub dport: String,
    #[serde(default)]
    pub target_ips: Vec<String>,
    #[serde(default)]
    pub enabled_modules: Vec<String>,
    #[serde(default = "default_project_action")]
    pub action: String,
}

fn default_project_action() -> String {
    "defend".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoIpConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// MaxMind/MMDB 数据库路径（预留，当前优先使用 CSV）
    pub db_path: Option<String>,
    /// 自定义国家/地区 CSV：`network,country_iso`（支持 IPv4/IPv6 CIDR）
    pub country_blocks_csv: Option<String>,
    /// 自定义 ASN CSV：`network,asn,asn_org`（支持 IPv4/IPv6 CIDR）
    pub asn_blocks_csv: Option<String>,
    #[serde(default)]
    pub block_countries: Vec<String>,
    #[serde(default)]
    pub allow_countries: Vec<String>,
    #[serde(default)]
    pub block_asns: Vec<u32>,
    #[serde(default)]
    pub allow_asns: Vec<u32>,
    #[serde(default = "default_geoip_action")]
    pub default_action: String,
}

fn default_geoip_action() -> String {
    "pass".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ThreatIntelConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub feeds: Vec<ThreatFeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub url: String,
    #[serde(default = "default_feed_interval_s")]
    pub interval_s: u64,
    #[serde(default = "default_feed_confidence")]
    pub confidence: u8,
    pub category: Option<String>,
    #[serde(default = "default_feed_action")]
    pub action: String,
}

fn default_feed_interval_s() -> u64 {
    3600
}

fn default_feed_confidence() -> u8 {
    80
}

fn default_feed_action() -> String {
    "drop".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_adaptive_threshold")]
    pub threshold: u64,
    #[serde(default = "default_adaptive_window_s")]
    pub window_s: u64,
    #[serde(default = "default_adaptive_block_duration_s")]
    pub block_duration_s: u64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 10,
            window_s: 5,
            block_duration_s: 300,
        }
    }
}

fn default_adaptive_threshold() -> u64 {
    10
}
fn default_adaptive_window_s() -> u64 {
    5
}
fn default_adaptive_block_duration_s() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize)]
pub struct SynProxyConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[allow(dead_code)]
    #[serde(default)]
    pub backend_ports: Vec<u16>,
    #[allow(dead_code)]
    #[serde(default = "default_syn_max_conns")]
    pub max_conns: u32,
    #[allow(dead_code)]
    #[serde(default = "default_syn_conn_timeout_s")]
    pub conn_timeout_s: u32,
}

impl Default for SynProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend_ports: Vec::new(),
            max_conns: 1024 * 1024,
            conn_timeout_s: 60,
        }
    }
}

fn default_syn_max_conns() -> u32 {
    1024 * 1024
}

fn default_syn_conn_timeout_s() -> u32 {
    60
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L7ScanConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<L7PatternConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7PatternConfig {
    pub pattern: String,
    #[serde(default)]
    pub mask: Option<String>,
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: u64,
    #[serde(default = "default_tick_ms")]
    pub tick_ms: u64,
    #[serde(default = "default_decay_num")]
    pub decay_num: u64,
    #[serde(default = "default_decay_den")]
    pub decay_den: u64,
    #[serde(default = "default_block_duration_s")]
    pub block_duration_s: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 200,
            tick_ms: 100,
            decay_num: 7,
            decay_den: 8,
            block_duration_s: 300,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_threshold() -> u64 {
    200
}
fn default_tick_ms() -> u64 {
    100
}
fn default_decay_num() -> u64 {
    7
}
fn default_decay_den() -> u64 {
    8
}
fn default_block_duration_s() -> u64 {
    300
}

/// 按目的端口限速参数：对（协议 + 目的端口）维度做速率限制，
/// 用于防换源 IP 绕过（源 IP 随机化时 per-IP 限速失效）。
/// 默认关闭，不影响既有行为；阈值默认高于 per-IP（聚合多源流量）。
#[derive(Debug, Clone, Deserialize)]
pub struct PortRateLimitConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_port_rate_threshold")]
    pub threshold: u64,
    #[serde(default = "default_tick_ms")]
    pub tick_ms: u64,
    #[serde(default = "default_decay_num")]
    pub decay_num: u64,
    #[serde(default = "default_decay_den")]
    pub decay_den: u64,
}

impl Default for PortRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 2000,
            tick_ms: 100,
            decay_num: 7,
            decay_den: 8,
        }
    }
}

fn default_port_rate_threshold() -> u64 {
    2000
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path).context("failed to read config file")?;
        let config: Config = toml::from_str(&content).context("failed to parse config file")?;
        Ok(config)
    }

    /// 校验配置合法性。
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.interface.is_empty() {
            anyhow::bail!("interface cannot be empty");
        }
        if !interface_exists(&self.interface) {
            anyhow::bail!(
                "network interface '{}' does not exist or is not visible",
                self.interface
            );
        }

        for cidr in &self.whitelist {
            crate::ip::parse_cidr(cidr)
                .with_context(|| format!("invalid whitelist CIDR: {}", cidr))?;
        }
        for ip in &self.blacklist {
            crate::ip::parse_ip_or_cidr(ip)
                .with_context(|| format!("invalid blacklist IP/CIDR: {}", ip))?;
        }

        // 持久化目录必须可创建
        if let Some(parent) = std::path::Path::new(&self.store_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("cannot create store directory: {}", parent.display())
                })?;
            }
        }

        validate_port_acl(self)?;

        if self.rate_limit.enabled {
            if self.rate_limit.threshold == 0 {
                anyhow::bail!("rate_limit.threshold must be > 0");
            }
            if self.rate_limit.tick_ms == 0 {
                anyhow::bail!("rate_limit.tick_ms must be > 0");
            }
            if self.rate_limit.decay_den == 0 {
                anyhow::bail!("rate_limit.decay_den must be > 0");
            }
        }

        if self.port_rate_limit.enabled {
            if self.port_rate_limit.threshold == 0 {
                anyhow::bail!("port_rate_limit.threshold must be > 0");
            }
            if self.port_rate_limit.tick_ms == 0 {
                anyhow::bail!("port_rate_limit.tick_ms must be > 0");
            }
            if self.port_rate_limit.decay_den == 0 {
                anyhow::bail!("port_rate_limit.decay_den must be > 0");
            }
        }

        if self.adaptive.enabled && self.adaptive.threshold == 0 {
            anyhow::bail!("adaptive.threshold must be > 0");
        }

        for (i, pat) in self.l7_scan.patterns.iter().enumerate() {
            let bytes = pat.pattern.as_bytes();
            if bytes.is_empty() {
                anyhow::bail!("L7 pattern {} cannot be empty", i);
            }
            if bytes.len() > 8 {
                anyhow::bail!("L7 pattern {} exceeds 8 bytes", i);
            }
            if let Some(mask) = &pat.mask {
                if mask.len() != bytes.len() {
                    anyhow::bail!("L7 pattern {} mask length mismatch", i);
                }
            }
        }

        if self.web_port == 0 {
            anyhow::bail!("web_port cannot be 0");
        }

        validate_geoip(self)?;
        validate_threat_intel(self)?;
        validate_protection_projects(self)?;
        validate_hub(self)?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn parse_blacklist(&self) -> anyhow::Result<Vec<IpKey>> {
        self.blacklist
            .iter()
            .map(|s| crate::ip::parse_ip_or_cidr(s))
            .collect::<anyhow::Result<Vec<_>>>()
    }
}

fn validate_port_acl(config: &Config) -> anyhow::Result<()> {
    for (i, entry) in config.port_acl.iter().enumerate() {
        let protocol = entry.protocol.to_lowercase();
        if !matches!(protocol.as_str(), "tcp" | "udp" | "icmp" | "icmpv6" | "any") {
            anyhow::bail!(
                "port_acl[{}]: invalid protocol '{}', expected tcp/udp/icmp/icmpv6/any",
                i,
                entry.protocol
            );
        }
        let action = entry.action.to_lowercase();
        if !matches!(action.as_str(), "allow" | "drop") {
            anyhow::bail!(
                "port_acl[{}]: invalid action '{}', expected allow/drop",
                i,
                entry.action
            );
        }
        if entry.dport == "*" || entry.dport == "any" {
            continue;
        }
        if let Some((low, high)) = entry.dport.split_once('-') {
            let low: u16 = low
                .parse()
                .with_context(|| format!("port_acl[{}]: invalid dport low", i))?;
            let high: u16 = high
                .parse()
                .with_context(|| format!("port_acl[{}]: invalid dport high", i))?;
            if low > high {
                anyhow::bail!("port_acl[{}]: invalid port range {}-{}", i, low, high);
            }
        } else {
            let _: u16 = entry
                .dport
                .parse()
                .with_context(|| format!("port_acl[{}]: invalid dport", i))?;
        }
    }
    Ok(())
}

fn interface_exists(iface: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(iface).exists()
}

fn validate_geoip(config: &Config) -> anyhow::Result<()> {
    if !config.geoip.enabled {
        return Ok(());
    }
    if !matches!(config.geoip.default_action.as_str(), "pass" | "drop") {
        anyhow::bail!(
            "geoip.default_action must be 'pass' or 'drop', got '{}'",
            config.geoip.default_action
        );
    }
    for code in &config.geoip.block_countries {
        if code.len() != 2 {
            anyhow::bail!(
                "geoip block country code must be ISO-3166-1 alpha-2: {}",
                code
            );
        }
    }
    for code in &config.geoip.allow_countries {
        if code.len() != 2 {
            anyhow::bail!(
                "geoip allow country code must be ISO-3166-1 alpha-2: {}",
                code
            );
        }
    }
    Ok(())
}

fn validate_threat_intel(config: &Config) -> anyhow::Result<()> {
    if !config.threat_intel.enabled {
        return Ok(());
    }
    for (i, feed) in config.threat_intel.feeds.iter().enumerate() {
        if feed.name.is_empty() {
            anyhow::bail!("threat_intel.feeds[{}]: name cannot be empty", i);
        }
        if feed.url.is_empty() {
            anyhow::bail!("threat_intel.feeds[{}]: url cannot be empty", i);
        }
        if feed.interval_s == 0 {
            anyhow::bail!("threat_intel.feeds[{}]: interval_s must be > 0", i);
        }
        if feed.confidence > 100 {
            anyhow::bail!("threat_intel.feeds[{}]: confidence must be 0-100", i);
        }
        if !matches!(feed.action.as_str(), "drop" | "allow") {
            anyhow::bail!(
                "threat_intel.feeds[{}]: action must be 'drop' or 'allow', got '{}'",
                i,
                feed.action
            );
        }
    }
    Ok(())
}

fn validate_hub(config: &Config) -> anyhow::Result<()> {
    if !config.hub.enabled {
        return Ok(());
    }
    if config.hub.node_name.is_empty() {
        anyhow::bail!("hub.node_name cannot be empty when hub is enabled");
    }
    if config.hub.urls.is_empty() {
        anyhow::bail!("hub.urls cannot be empty when hub is enabled");
    }
    if config.hub.token.is_empty() {
        anyhow::bail!("hub.token cannot be empty when hub is enabled");
    }
    for (i, url) in config.hub.urls.iter().enumerate() {
        if url.is_empty() {
            anyhow::bail!("hub.urls[{}] cannot be empty", i);
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            anyhow::bail!("hub.urls[{}] must start with http:// or https://", i);
        }
    }
    if config.hub.sync_pull_interval_s == 0 {
        anyhow::bail!("hub.sync_pull_interval_s must be > 0");
    }
    if config.hub.sync_push_interval_s == 0 {
        anyhow::bail!("hub.sync_push_interval_s must be > 0");
    }
    if config.hub.push_min_hit_count == 0 {
        anyhow::bail!("hub.push_min_hit_count must be > 0");
    }
    if config.hub.sync_rules_interval_s == 0 {
        anyhow::bail!("hub.sync_rules_interval_s must be > 0");
    }
    Ok(())
}

fn validate_protection_projects(config: &Config) -> anyhow::Result<()> {
    let valid_modules: std::collections::HashSet<&str> = [
        "syn_flood",
        "udp_flood",
        "icmp_flood",
        "rate_limit",
        "adaptive",
        "l7_scan",
        "geoip",
        "tcp_reset",
        "port_acl",
    ]
    .into_iter()
    .collect();
    for (i, proj) in config.protection_projects.iter().enumerate() {
        if proj.name.is_empty() {
            anyhow::bail!("protection_projects[{}]: name cannot be empty", i);
        }
        if !matches!(
            proj.protocol.to_lowercase().as_str(),
            "tcp" | "udp" | "icmp" | "icmpv6" | "any"
        ) {
            anyhow::bail!(
                "protection_projects[{}]: invalid protocol '{}', expected tcp/udp/icmp/icmpv6/any",
                i,
                proj.protocol
            );
        }
        if proj.dport.is_empty() {
            anyhow::bail!("protection_projects[{}]: dport cannot be empty", i);
        }
        if proj.dport != "any" {
            let _: u16 = proj
                .dport
                .parse()
                .with_context(|| format!("protection_projects[{}]: invalid dport", i))?;
        }
        if !matches!(
            proj.action.to_lowercase().as_str(),
            "pass" | "drop" | "defend"
        ) {
            anyhow::bail!(
                "protection_projects[{}]: invalid action '{}', expected pass/drop/defend",
                i,
                proj.action
            );
        }
        for (j, m) in proj.enabled_modules.iter().enumerate() {
            if !valid_modules.contains(m.as_str()) {
                anyhow::bail!(
                    "protection_projects[{}].enabled_modules[{}]: unknown module '{}'",
                    i,
                    j,
                    m
                );
            }
        }
        for (j, ip) in proj.target_ips.iter().enumerate() {
            // 纯 IP 直接合法；CIDR 支持 /24 及以上网段（数据面按精确 IP 匹配，
            // 控制面展开，过宽网段会撑爆 PROJECT_POLICY map，故拒绝）
            if crate::ip::parse_ip(ip).is_ok() {
                continue;
            }
            let (key, prefix) = crate::ip::parse_cidr(ip).with_context(|| {
                format!(
                    "protection_projects[{}].target_ips[{}]: invalid IP/CIDR",
                    i, j
                )
            })?;
            if key.family() == Some(eshield_common::IpFamily::Ipv4) && prefix < 24 {
                anyhow::bail!(
                    "protection_projects[{}].target_ips[{}]: CIDR /{} too broad (min /24, expanded to exact IPs)",
                    i,
                    j,
                    prefix
                );
            }
        }
    }
    Ok(())
}

impl PortAclItem {
    pub fn to_entry(&self) -> anyhow::Result<PortAclEntry> {
        let protocol = match self.protocol.to_lowercase().as_str() {
            "any" => 0u8,
            "tcp" => 6u8,
            "udp" => 17u8,
            "icmp" => 1u8,
            "icmpv6" => 58u8,
            _ => anyhow::bail!("invalid protocol: {}", self.protocol),
        };
        let action = match self.action.to_lowercase().as_str() {
            "allow" => 1u8,
            "drop" => 2u8,
            _ => anyhow::bail!("invalid action: {}", self.action),
        };
        let (low, high) = if self.dport == "*" || self.dport == "any" {
            (0u16, 0u16)
        } else if let Some((a, b)) = self.dport.split_once('-') {
            let low: u16 = a.parse().context("invalid dport low")?;
            let high: u16 = b.parse().context("invalid dport high")?;
            if low > high {
                anyhow::bail!("invalid port range");
            }
            (low, high)
        } else {
            let p: u16 = self.dport.parse().context("invalid dport")?;
            (p, p)
        };
        Ok(PortAclEntry {
            protocol,
            dport_low: u16::to_be(low),
            dport_high: u16::to_be(high),
            action,
            padding: [0; 11],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eshield_common::IpFamily;

    #[test]
    fn test_parse_ip_ipv4_ok() {
        let key = crate::ip::parse_ip("192.0.2.1").unwrap();
        assert_eq!(key.family, IpFamily::Ipv4 as u8);
        assert_eq!(key.ipv4(), 0xc000_0201);
    }

    #[test]
    fn test_parse_ip_ipv6_ok() {
        let key = crate::ip::parse_ip("2001:db8::1").unwrap();
        assert_eq!(key.family, IpFamily::Ipv6 as u8);
        let expected: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(key.addr, expected);
    }

    #[test]
    fn test_parse_cidr_ipv4_ok() {
        let (key, prefix) = crate::ip::parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(prefix, 8);
        assert_eq!(key.family, IpFamily::Ipv4 as u8);
        assert_eq!(key.ipv4(), 0x0a00_0000);
    }

    #[test]
    fn test_parse_cidr_ipv6_ok() {
        let (key, prefix) = crate::ip::parse_cidr("2001:db8::/32").unwrap();
        assert_eq!(prefix, 32);
        assert_eq!(key.family, IpFamily::Ipv6 as u8);
        assert_eq!(&key.addr[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        assert!(key.addr[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_rejected() {
        assert!(crate::ip::parse_cidr("192.0.2.0/33").is_err());
        assert!(crate::ip::parse_cidr("2001:db8::/129").is_err());
    }

    #[test]
    fn test_port_acl_item_to_entry() {
        let item = PortAclItem {
            protocol: "tcp".to_string(),
            dport: "80".to_string(),
            action: "drop".to_string(),
        };
        let entry = item.to_entry().unwrap();
        assert_eq!(entry.protocol, 6);
        // eBPF Map 中端口按网络字节序存储，因此断言也要用网络字节序。
        assert_eq!(entry.dport_low, u16::to_be(80));
        assert_eq!(entry.dport_high, u16::to_be(80));
        assert_eq!(entry.action, 2);
    }

    #[test]
    fn test_port_acl_item_range_to_entry() {
        let item = PortAclItem {
            protocol: "udp".to_string(),
            dport: "1000-2000".to_string(),
            action: "allow".to_string(),
        };
        let entry = item.to_entry().unwrap();
        assert_eq!(entry.protocol, 17);
        assert_eq!(entry.dport_low, u16::to_be(1000));
        assert_eq!(entry.dport_high, u16::to_be(2000));
        assert_eq!(entry.action, 1);
    }

    #[test]
    fn test_port_acl_item_any_to_entry() {
        let item = PortAclItem {
            protocol: "any".to_string(),
            dport: "any".to_string(),
            action: "drop".to_string(),
        };
        let entry = item.to_entry().unwrap();
        assert_eq!(entry.protocol, 0);
        assert_eq!(entry.dport_low, 0);
        assert_eq!(entry.dport_high, 0);
        assert_eq!(entry.action, 2);
    }
}

use anyhow::Context;
use eshield_common::{IpKey, PortAclEntry};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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
}

fn default_web_port() -> u16 {
    8720
}

fn default_store_path() -> String {
    "/var/lib/eshield/rules.redb".to_string()
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
fn default_trust_add_divisor() -> u32 { 100 }
fn default_trust_sub_divisor() -> u32 { 3 }

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
fn default_danger_sample_s() -> u64 { 5 }
fn default_danger_anomaly_multiplier() -> f64 { 2.0 }

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
            anyhow::bail!("geoip block country code must be ISO-3166-1 alpha-2: {}", code);
        }
    }
    for code in &config.geoip.allow_countries {
        if code.len() != 2 {
            anyhow::bail!("geoip allow country code must be ISO-3166-1 alpha-2: {}", code);
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
        if !matches!(proj.protocol.to_lowercase().as_str(), "tcp" | "udp" | "icmp" | "icmpv6" | "any") {
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
        if !matches!(proj.action.to_lowercase().as_str(), "pass" | "drop" | "defend") {
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
            crate::ip::parse_ip_or_cidr(ip).with_context(|| {
                format!("protection_projects[{}].target_ips[{}]: invalid IP/CIDR", i, j)
            })?;
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
        assert_eq!(entry.dport_low, 80);
        assert_eq!(entry.dport_high, 80);
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
        assert_eq!(entry.dport_low, 1000);
        assert_eq!(entry.dport_high, 2000);
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

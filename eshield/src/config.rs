use anyhow::Context;
use eshield_common::{IpKey, PortAclEntry};
use serde::Deserialize;
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
    #[serde(default = "default_alert_threshold_dps")]
    pub alert_threshold_dps: u64,
    #[serde(default = "default_alert_cooldown_s")]
    pub alert_cooldown_s: u64,
}

fn default_web_port() -> u16 {
    8443
}

fn default_store_path() -> String {
    "/var/lib/eshield/rules.redb".to_string()
}

fn default_alert_threshold_dps() -> u64 {
    1000
}

fn default_alert_cooldown_s() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortAclItem {
    pub protocol: String,
    pub dport: String,
    pub action: String,
}

#[derive(Debug, Clone, Deserialize)]
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
            enabled: true,
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

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SynProxyConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct L7ScanConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<L7PatternConfig>,
}

#[derive(Debug, Clone, Deserialize)]
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
            dport_low: low,
            dport_high: high,
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

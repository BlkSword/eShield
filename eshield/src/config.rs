use anyhow::Context;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
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
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub syn_proxy: SynProxyConfig,
    #[serde(default)]
    pub l7_scan: L7ScanConfig,
    #[serde(default)]
    pub adaptive: AdaptiveConfig,
    #[serde(default = "default_web_port")]
    pub web_port: u16,
}

fn default_web_port() -> u16 {
    8443
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
            parse_cidr(cidr).with_context(|| format!("invalid whitelist CIDR: {}", cidr))?;
        }
        for ip in &self.blacklist {
            parse_ip(ip).with_context(|| format!("invalid blacklist IP: {}", ip))?;
        }

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
    pub fn parse_blacklist(&self) -> anyhow::Result<Vec<u32>> {
        self.blacklist
            .iter()
            .map(|s| parse_ip(s))
            .collect::<anyhow::Result<Vec<_>>>()
    }
}

fn interface_exists(iface: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(iface).exists()
}

pub fn parse_ip(s: &str) -> anyhow::Result<u32> {
    let addr: IpAddr = s.parse().context("invalid IP address")?;
    match addr {
        IpAddr::V4(v4) => Ok(u32::from_be_bytes(v4.octets())),
        IpAddr::V6(_) => anyhow::bail!("IPv6 is not supported yet"),
    }
}

fn parse_cidr(s: &str) -> anyhow::Result<(u32, u32)> {
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

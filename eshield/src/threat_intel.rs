use crate::control::ControlState;
use crate::ip::{format_ip_key, parse_ip_or_cidr};
use anyhow::{Context, Result};
use eshield_common::IpKey;
use std::sync::Arc;
use std::time::Duration;

/// 后台威胁情报同步器。
pub struct ThreatIntelSync {
    control: Arc<ControlState>,
}

impl ThreatIntelSync {
    pub fn new(control: Arc<ControlState>) -> Self {
        Self { control }
    }

    /// 启动所有 feed 的后台同步任务。
    pub async fn run(&self, config: crate::config::ThreatIntelConfig) {
        sync_all_feeds(self.control.clone(), config.feeds).await;
    }
}

/// 同步所有威胁情报 feed（后台循环入口）。
pub async fn sync_all_feeds(control: Arc<ControlState>, feeds: Vec<crate::config::ThreatFeed>) {
    if feeds.is_empty() {
        return;
    }

    for feed in feeds {
        let control = control.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(feed.interval_s));
            // 首次立即执行一次
            if let Err(e) = sync_feed(&control, &feed).await {
                tracing::warn!(
                    "threat intel feed '{}' initial sync failed: {}",
                    feed.name,
                    e
                );
            }
            loop {
                interval.tick().await;
                if let Err(e) = sync_feed(&control, &feed).await {
                    tracing::warn!(
                        "threat intel feed '{}' sync failed: {}",
                        feed.name,
                        e
                    );
                }
            }
        });
    }
}

/// 立即同步单个 feed（手动触发用）。
pub async fn sync_feed_now(control: Arc<ControlState>, feed: crate::config::ThreatFeed) -> Result<()> {
    sync_feed(&control, &feed).await
}

async fn sync_feed(control: &ControlState, feed: &crate::config::ThreatFeed) -> Result<()> {
    tracing::info!("syncing threat intel feed '{}' from {}", feed.name, feed.url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("eShield/0.2.0")
        .build()
        .context("build http client")?;

    let resp = client.get(&feed.url).send().await.with_context(|| {
        format!("fetch threat intel feed '{}' from {}", feed.name, feed.url)
    })?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "feed '{}' returned status {}",
            feed.name,
            resp.status()
        );
    }

    let text = resp.text().await.context("read feed response body")?;
    let entries = parse_feed(&text, feed).context("parse feed")?;

    let mut added = 0u64;
    let mut skipped = 0u64;

    match feed.action.as_str() {
        "drop" => {
            // 存活时间：默认 24 小时，确保在下次同步前不过期
            let duration_s = feed.interval_s.saturating_mul(3).max(3600);
            for key in entries {
                if let Err(e) = control.block_ip_threat_intel(key, duration_s).await {
                    tracing::debug!("skip threat intel block for {}: {}", format_ip_key(&key), e);
                    skipped += 1;
                } else {
                    added += 1;
                }
            }
        }
        "allow" => {
            for (key, prefix) in entries_cidr(entries) {
                if let Err(e) = control.allow_cidr_raw(key, prefix).await {
                    tracing::debug!("skip threat intel allow for {}/{}: {}", format_ip_key(&key), prefix, e);
                    skipped += 1;
                } else {
                    added += 1;
                }
            }
        }
        other => anyhow::bail!("unsupported threat intel action: {}", other),
    }

    tracing::info!(
        "threat intel feed '{}' sync complete: added={}, skipped={}",
        feed.name,
        added,
        skipped
    );
    Ok(())
}

/// 解析 feed 内容，返回 IP/CIDR 列表。
fn parse_feed(text: &str, _feed: &crate::config::ThreatFeed) -> Result<Vec<IpKey>> {
    let trimmed = text.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        parse_json_feed(text)
    } else {
        parse_text_feed(text)
    }
}

fn parse_json_feed(text: &str) -> Result<Vec<IpKey>> {
    let mut result = Vec::new();
    let json: serde_json::Value = serde_json::from_str(text).context("parse JSON feed")?;

    // AbuseIPDB v2 blacklist endpoint format: { "data": [ { "ipAddress": "..." }, ... ] }
    if let Some(data) = json.get("data").and_then(|v| v.as_array()) {
        for item in data {
            if let Some(ip) = item.get("ipAddress").and_then(|v| v.as_str()) {
                add_ip(&mut result, ip);
            }
        }
    }

    // Generic JSON array of strings
    if let Some(arr) = json.as_array() {
        for item in arr {
            if let Some(ip) = item.as_str() {
                add_ip(&mut result, ip);
            } else if let Some(ip) = item.get("ip").and_then(|v| v.as_str()) {
                add_ip(&mut result, ip);
            }
        }
    }

    Ok(result)
}

fn parse_text_feed(text: &str) -> Result<Vec<IpKey>> {
    let mut result = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // CSV or plain text: first column is the IP/CIDR
        let ip_str = line.split(',').next().unwrap_or(line).trim();
        if ip_str.is_empty() {
            continue;
        }
        add_ip(&mut result, ip_str);
    }
    Ok(result)
}

fn add_ip(out: &mut Vec<IpKey>, s: &str) {
    match parse_ip_or_cidr(s) {
        Ok(key) => out.push(key),
        Err(e) => tracing::debug!("skip invalid threat intel entry '{}': {}", s, e),
    }
}

fn entries_cidr(entries: Vec<IpKey>) -> Vec<(IpKey, u32)> {
    entries
        .into_iter()
        .map(|key| match key.family() {
            Some(eshield_common::IpFamily::Ipv4) => (key, 32),
            Some(eshield_common::IpFamily::Ipv6) => (key, 128),
            None => (key, 128),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ThreatFeed, ThreatIntelConfig};

    #[test]
    fn test_parse_text_feed_plain() {
        let feed = ThreatFeed {
            name: "test".to_string(),
            url: "http://test".to_string(),
            interval_s: 60,
            confidence: 80,
            category: None,
            action: "drop".to_string(),
        };
        let text = "# comment\n192.0.2.1\n2001:db8::1\n\n";
        let entries = parse_feed(text, &feed).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_text_feed_csv() {
        let feed = ThreatFeed {
            name: "test".to_string(),
            url: "http://test".to_string(),
            interval_s: 60,
            confidence: 80,
            category: None,
            action: "drop".to_string(),
        };
        let text = "192.0.2.0/24,US,malware\n2001:db8::/32,CN\n";
        let entries = parse_feed(text, &feed).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_json_feed_abuseipdb() {
        let feed = ThreatFeed {
            name: "test".to_string(),
            url: "http://test".to_string(),
            interval_s: 60,
            confidence: 80,
            category: None,
            action: "drop".to_string(),
        };
        let text = r#"{"data":[{"ipAddress":"192.0.2.5"},{"ipAddress":"2001:db8::5"}]}"#;
        let entries = parse_feed(text, &feed).unwrap();
        assert_eq!(entries.len(), 2);
    }
}

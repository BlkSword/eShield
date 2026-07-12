use crate::models::NodePolicy;
use crate::store::Store;
use anyhow::{Context, Result};
use eshield_common::{rules, IpKey};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Hub 侧威胁情报 feed 配置。
#[derive(Clone, Debug)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub interval_s: u64,
    pub action: String,
    pub ttl_s: u64,
}

/// 启动 Hub 威胁情报拉取任务：定时从远程 feed 获取 IP，合并为共享策略。
pub fn spawn_feed_sync(config: FeedConfig, store: Arc<Store>) {
    if config.url.is_empty() {
        return;
    }
    tokio::spawn(async move {
        // 首次立即执行一次
        if let Err(e) = sync_once(&config, &store).await {
            tracing::warn!("hub threat feed initial sync failed: {}", e);
        }
        let mut interval = tokio::time::interval(Duration::from_secs(config.interval_s));
        loop {
            interval.tick().await;
            if let Err(e) = sync_once(&config, &store).await {
                tracing::warn!("hub threat feed sync failed: {}", e);
            }
        }
    });
}

async fn sync_once(config: &FeedConfig, store: &Store) -> Result<()> {
    tracing::info!(
        feed = %config.name,
        url = %config.url,
        "syncing hub threat feed"
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("eShield-Hub/0.5.0")
        .build()
        .context("build feed HTTP client")?;

    let resp = client
        .get(&config.url)
        .send()
        .await
        .with_context(|| format!("fetch feed from {}", config.url))?;

    if !resp.status().is_success() {
        anyhow::bail!("feed returned status {}", resp.status());
    }

    let text = resp.text().await.context("read feed body")?;
    let entries = parse_feed(&text).context("parse feed")?;

    if config.action != "drop" {
        tracing::debug!("hub feed action '{}' is not supported yet", config.action);
        return Ok(());
    }

    let policies: Vec<NodePolicy> = entries
        .into_iter()
        .map(|ip| NodePolicy {
            ip,
            reason: rules::THREAT_INTEL as u8,
            hit_count: 1,
            trust_score: 0,
            blocked_until_ns: 0,
            ttl_s: config.ttl_s,
        })
        .collect();

    if policies.is_empty() {
        tracing::info!("hub threat feed yielded no entries");
        return Ok(());
    }

    let merged = store.merge(&config.name, &policies)?;
    tracing::info!(
        feed = %config.name,
        total = policies.len(),
        merged,
        "hub threat feed merged"
    );
    Ok(())
}

fn parse_feed(text: &str) -> Result<Vec<IpKey>> {
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

    if let Some(data) = json.get("data").and_then(|v| v.as_array()) {
        for item in data {
            if let Some(ip) = item.get("ipAddress").and_then(|v| v.as_str()) {
                add_ip(&mut result, ip);
            }
        }
    }

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
        // CSV 或纯文本：第一列为 IP/CIDR
        let ip_str = line.split(',').next().unwrap_or(line).trim();
        if ip_str.is_empty() {
            continue;
        }
        // 去掉 CIDR 后缀，只取网络地址（/32 与 /128 即主机本身）
        let ip_str = ip_str.split_once('/').map(|(ip, _)| ip).unwrap_or(ip_str);
        add_ip(&mut result, ip_str);
    }
    Ok(result)
}

fn add_ip(out: &mut Vec<IpKey>, s: &str) {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => out.push(IpKey::from_ipv4(v4.octets())),
        Ok(IpAddr::V6(v6)) => out.push(IpKey::from_ipv6(v6.octets())),
        Err(e) => tracing::debug!("skip invalid threat intel entry '{}': {}", s, e),
    }
}

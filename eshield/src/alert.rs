use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::ip::format_ip_key;
use crate::state::Stats;

/// 告警配置
#[derive(Clone, Debug, Default)]
pub struct AlertConfig {
    pub webhook_url: Option<String>,
    pub webhook_type: String,
    /// 每秒 DROP 包数阈值
    pub threshold_dps: u64,
    /// 告警最小间隔（秒）
    pub cooldown_s: u64,
    /// 监控网卡
    pub interface: String,
}

/// 攻击者摘要
#[derive(Clone, Debug, Serialize)]
pub struct AlertAttacker {
    pub ip: String,
    pub count: u64,
}

/// 告警事件
#[derive(Clone, Debug, Serialize)]
pub struct AlertEvent {
    pub timestamp: u64,
    pub interface: String,
    pub alert_type: String,
    pub total_dropped: u64,
    pub dps: u64,
    pub threshold_dps: u64,
    pub cooldown_s: u64,
    pub message: String,
    pub rule_breakdown: HashMap<String, u64>,
    pub top_attackers: Vec<AlertAttacker>,
}

pub struct AlertManager {
    config: AlertConfig,
    client: reqwest::Client,
    last_alert_s: Mutex<u64>,
}

impl AlertManager {
    pub fn new(config: AlertConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            client: reqwest::Client::new(),
            last_alert_s: Mutex::new(0),
        })
    }

    /// 根据当前总 DROP 数检查是否触发告警。调用方应周期性传入 window_s 内的增量。
    pub async fn check(&self, stats: &Stats, delta: u64, window_s: u64) {
        if window_s == 0 || self.config.webhook_url.is_none() {
            return;
        }
        let dps = delta / window_s;
        if dps < self.config.threshold_dps {
            return;
        }

        let now_s = now_s();
        let mut last = self.last_alert_s.lock().await;
        if now_s.saturating_sub(*last) < self.config.cooldown_s {
            return;
        }
        *last = now_s;
        drop(last);

        let rule_breakdown = {
            let mut m = HashMap::new();
            m.insert("blacklist".to_string(), stats.blacklist_blocked.load(Ordering::Relaxed));
            m.insert("rate_limit".to_string(), stats.rate_limited.load(Ordering::Relaxed));
            m.insert("syn_flood".to_string(), stats.syn_flood_blocked.load(Ordering::Relaxed));
            m.insert("l7".to_string(), stats.l7_blocked.load(Ordering::Relaxed));
            m.insert("adaptive".to_string(), stats.adaptive_blocked.load(Ordering::Relaxed));
            m.insert("udp_flood".to_string(), stats.udp_flood_blocked.load(Ordering::Relaxed));
            m.insert("icmp_flood".to_string(), stats.icmp_flood_blocked.load(Ordering::Relaxed));
            m.insert("waf".to_string(), stats.waf_blocked.load(Ordering::Relaxed));
            m.insert("geoip".to_string(), stats.geoip_blocked.load(Ordering::Relaxed));
            m.insert("challenge".to_string(), stats.challenge_issued.load(Ordering::Relaxed));
            m
        };

        let mut top_attackers: Vec<AlertAttacker> = stats
            .top_attackers
            .iter()
            .map(|e| AlertAttacker {
                ip: format_ip_key(e.key()),
                count: e.value().load(Ordering::Relaxed),
            })
            .collect();
        top_attackers.sort_by_key(|a| std::cmp::Reverse(a.count));
        top_attackers.truncate(5);

        let event = AlertEvent {
            timestamp: now_s,
            interface: self.config.interface.clone(),
            alert_type: "drop_rate".to_string(),
            total_dropped: stats.total_dropped.load(Ordering::Relaxed),
            dps,
            threshold_dps: self.config.threshold_dps,
            cooldown_s: self.config.cooldown_s,
            message: format!(
                "eShield [{}] 告警：DROP 速率 {} pps 超过阈值 {} pps",
                self.config.interface, dps, self.config.threshold_dps
            ),
            rule_breakdown,
            top_attackers,
        };

        if let Some(url) = &self.config.webhook_url {
            let payload = self.format_payload(&event);
            if let Err(e) = self.client.post(url).json(&payload).send().await {
                tracing::warn!("failed to send alert webhook: {}", e);
            }
        }
    }

    fn format_payload(&self, event: &AlertEvent) -> serde_json::Value {
        match self.config.webhook_type.as_str() {
            "slack" => serde_json::json!({
                "text": event.message,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!(
                                "*eShield {} 告警*\nDROP 速率：{} pps\n阈值：{} pps\n总丢弃：{}\nTOP 攻击源：{}",
                                event.interface,
                                event.dps,
                                event.threshold_dps,
                                event.total_dropped,
                                event.top_attackers.iter().map(|a| format!("{}({})", a.ip, a.count)).collect::<Vec<_>>().join(", ")
                            )
                        }
                    }
                ]
            }),
            "dingtalk" => serde_json::json!({
                "msgtype": "text",
                "text": {
                    "content": format!(
                        "{}\n规则分布：{}\nTOP：{}",
                        event.message,
                        serde_json::to_string(&event.rule_breakdown).unwrap_or_default(),
                        event.top_attackers.iter().map(|a| format!("{}({})", a.ip, a.count)).collect::<Vec<_>>().join(", ")
                    )
                }
            }),
            "wecom" | "wechat" => serde_json::json!({
                "msgtype": "text",
                "text": {
                    "content": format!(
                        "{}\n规则分布：{}\nTOP：{}",
                        event.message,
                        serde_json::to_string(&event.rule_breakdown).unwrap_or_default(),
                        event.top_attackers.iter().map(|a| format!("{}({})", a.ip, a.count)).collect::<Vec<_>>().join(", ")
                    )
                }
            }),
            _ => serde_json::to_value(event).unwrap_or_default(),
        }
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

use serde::Serialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// 告警配置
#[derive(Clone, Debug, Default)]
pub struct AlertConfig {
    pub webhook_url: Option<String>,
    /// 每秒 DROP 包数阈值
    pub threshold_dps: u64,
    /// 告警最小间隔（秒）
    pub cooldown_s: u64,
}

/// 告警事件
#[derive(Clone, Debug, Serialize)]
pub struct AlertEvent {
    pub timestamp: u64,
    pub total_dropped: u64,
    pub dps: u64,
    pub message: String,
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
    pub async fn check(&self, total_dropped: u64, window_s: u64) {
        if window_s == 0 || self.config.webhook_url.is_none() {
            return;
        }
        let dps = total_dropped / window_s;
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

        let event = AlertEvent {
            timestamp: now_s,
            total_dropped,
            dps,
            message: format!(
                "eShield alert: drop rate {} pps exceeds threshold {} pps",
                dps, self.config.threshold_dps
            ),
        };

        if let Some(url) = &self.config.webhook_url {
            if let Err(e) = self.client.post(url).json(&event).send().await {
                tracing::warn!("failed to send alert webhook: {}", e);
            }
        }
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

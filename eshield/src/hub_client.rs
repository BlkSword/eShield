use crate::config::{HubConfig, HubTlsConfig};
use crate::control::ControlState;
use anyhow::{Context, Result};
use eshield_common::IpKey;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

/// Node 上报给 Hub 的单条策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePolicy {
    pub ip: IpKey,
    pub reason: u8,
    pub hit_count: u32,
    pub trust_score: u32,
    pub blocked_until_ns: u64,
    pub ttl_s: u64,
}

/// Node 上报请求体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPush {
    pub node_name: String,
    pub policies: Vec<NodePolicy>,
}

/// Hub 返回的共享策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPolicy {
    pub ip: IpKey,
    pub reason: u8,
    pub hit_count: u32,
    pub trust_score: u32,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub source_nodes: Vec<String>,
    pub ttl_s: u64,
}

/// Hub 拉取响应体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPull {
    pub policies: Vec<SharedPolicy>,
    pub cursor: String,
    #[serde(default)]
    pub deleted: Vec<IpKey>,
    #[serde(default)]
    pub deleted_cursor: String,
}

/// 被 Hub 删除的策略。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedPolicies {
    pub ips: Vec<IpKey>,
    pub cursor: String,
}

/// Hub 统一下发的规则包（字段与 eshield 配置类型一致）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBundle {
    pub port_acl: Vec<crate::config::PortAclItem>,
    pub l7_patterns: Vec<crate::config::L7PatternConfig>,
    pub protection_projects: Vec<crate::config::ProtectionProject>,
    pub updated_at_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesResponse {
    pub rules: Option<RuleBundle>,
}

/// Hub 节点心跳请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    pub node_name: String,
    pub stats: Option<serde_json::Value>,
}

/// Hub 通信客户端。
pub struct HubClient {
    config: HubConfig,
    http: reqwest::Client,
    control: Arc<ControlState>,
    last_push_ns: AtomicU64,
    last_pull_ns: AtomicU64,
    last_deleted_ns: AtomicU64,
    last_rules_ns: AtomicU64,
    current_url_idx: AtomicUsize,
    connected: AtomicBool,
}

impl HubClient {
    pub fn new(config: HubConfig, control: Arc<ControlState>) -> Result<Self> {
        let http = build_http_client(&config.tls).context("failed to build hub HTTP client")?;
        Ok(Self {
            config,
            http,
            control,
            last_push_ns: AtomicU64::new(0),
            last_pull_ns: AtomicU64::new(0),
            last_deleted_ns: AtomicU64::new(0),
            last_rules_ns: AtomicU64::new(0),
            current_url_idx: AtomicUsize::new(0),
            connected: AtomicBool::new(false),
        })
    }

    pub async fn run(&self) {
        tracing::info!(
            node_name = %self.config.node_name,
            urls = ?self.config.urls,
            "hub client started"
        );

        let push_interval = Duration::from_secs(self.config.sync_push_interval_s);
        let pull_interval = Duration::from_secs(self.config.sync_pull_interval_s);
        let heartbeat_interval = Duration::from_secs(30);

        let push_handle = {
            let client = self.clone_ref();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(push_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = client.push_once().await {
                        tracing::warn!("hub push failed: {}", e);
                    }
                }
            })
        };

        let pull_handle = {
            let client = self.clone_ref();
            tokio::spawn(async move {
                // 首次立即拉取一次
                if let Err(e) = client.pull_once().await {
                    tracing::warn!("hub initial pull failed: {}", e);
                }
                let mut interval = tokio::time::interval(pull_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = client.pull_once().await {
                        tracing::warn!("hub pull failed: {}", e);
                    }
                }
            })
        };

        let heartbeat_handle = {
            let client = self.clone_ref();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(heartbeat_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = client.heartbeat_once().await {
                        tracing::debug!("hub heartbeat failed: {}", e);
                    }
                }
            })
        };

        let rules_handle = {
            let client = self.clone_ref();
            tokio::spawn(async move {
                if client.config.sync_rules_enabled {
                    let mut interval = tokio::time::interval(Duration::from_secs(
                        client.config.sync_rules_interval_s.max(1)
                    ));
                    loop {
                        interval.tick().await;
                        if let Err(e) = client.sync_rules_once().await {
                            tracing::debug!("hub rules sync failed: {}", e);
                        }
                    }
                }
            })
        };

        let _ = tokio::join!(push_handle, pull_handle, heartbeat_handle, rules_handle);
        tracing::warn!("hub client loops exited unexpectedly");
    }

    fn clone_ref(&self) -> Arc<HubClient> {
        Arc::new(HubClient {
            config: self.config.clone(),
            http: self.http.clone(),
            control: self.control.clone(),
            last_push_ns: AtomicU64::new(self.last_push_ns.load(Ordering::Relaxed)),
            last_pull_ns: AtomicU64::new(self.last_pull_ns.load(Ordering::Relaxed)),
            last_deleted_ns: AtomicU64::new(self.last_deleted_ns.load(Ordering::Relaxed)),
            last_rules_ns: AtomicU64::new(self.last_rules_ns.load(Ordering::Relaxed)),
            current_url_idx: AtomicUsize::new(self.current_url_idx.load(Ordering::Relaxed)),
            connected: AtomicBool::new(self.connected.load(Ordering::Relaxed)),
        })
    }

    async fn push_once(&self) -> Result<()> {
        let since_ns = self.last_push_ns.load(Ordering::Relaxed);
        let policies = self
            .control
            .collect_hub_publishable_policies(
                since_ns,
                self.config.push_min_hit_count,
                self.config.push_min_trust,
                self.config.push_max_batch_size,
            )
            .await?;
        if policies.is_empty() {
            return Ok(());
        }

        let body = PolicyPush {
            node_name: self.config.node_name.clone(),
            policies,
        };
        let (url, resp) = self
            .post_with_failover("/api/v1/policies", &body)
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("hub {} returned {}: {}", url, status, text);
        }

        let now_ns = crate::time::monotonic_ns();
        self.last_push_ns.store(now_ns, Ordering::Relaxed);
        tracing::info!(
            node_name = %self.config.node_name,
            hub = %url,
            count = body.policies.len(),
            "pushed policies to hub"
        );
        Ok(())
    }

    async fn pull_once(&self) -> Result<()> {
        let since_ns = self.last_pull_ns.load(Ordering::Relaxed);
        let path = format!("/api/v1/policies?since={}&limit=100", since_ns);
        let (url, resp) = self.get_with_failover(&path).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("hub {} returned {}: {}", url, status, text);
        }

        let pull: PolicyPull = resp.json().await.context("failed to parse policy pull")?;
        let applied = self.control.apply_hub_policies(&pull.policies).await?;
        if let Ok(cursor) = pull.cursor.parse::<u64>() {
            self.last_pull_ns.store(cursor, Ordering::Relaxed);
        }
        if applied > 0 {
            tracing::info!(
                node_name = %self.config.node_name,
                hub = %url,
                applied,
                "applied policies from hub"
            );
        }

        // 同步 Hub 侧已删除的策略（解封）。
        if let Err(e) = self.pull_deleted_once().await {
            tracing::debug!("hub deleted policies sync failed: {}", e);
        }

        Ok(())
    }

    async fn pull_deleted_once(&self) -> Result<()> {
        let since_ns = self.last_deleted_ns.load(Ordering::Relaxed);
        let path = format!("/api/v1/policies/deleted?since={}&limit=100", since_ns);
        let (_url, resp) = self.get_with_failover(&path).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("hub deleted policies returned {}: {}", status, text);
        }

        let deleted: DeletedPolicies = resp.json().await.context("parse deleted policies")?;
        let unblocked = self.control.unblock_hub_policies(&deleted.ips).await?;
        if let Ok(cursor) = deleted.cursor.parse::<u64>() {
            self.last_deleted_ns.store(cursor, Ordering::Relaxed);
        }
        if unblocked > 0 {
            tracing::info!(
                node_name = %self.config.node_name,
                unblocked,
                "unblocked policies deleted by hub"
            );
        }
        Ok(())
    }

    async fn sync_rules_once(&self) -> Result<()> {
        let (_url, resp) = self.get_with_failover("/api/v1/rules").await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("hub rules returned {}: {}", status, text);
        }
        let body: RulesResponse = resp.json().await.context("parse rules response")?;
        let Some(bundle) = body.rules else {
            return Ok(());
        };
        if bundle.updated_at_ns <= self.last_rules_ns.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.control.apply_hub_rules(&bundle).await?;
        self.last_rules_ns
            .store(bundle.updated_at_ns, Ordering::Relaxed);
        tracing::info!(
            node_name = %self.config.node_name,
            updated_at_ns = bundle.updated_at_ns,
            "applied rules from hub"
        );
        Ok(())
    }

    async fn heartbeat_once(&self) -> Result<()> {
        let stats = self.control.stats_snapshot_json().await;
        let body = NodeHeartbeat {
            node_name: self.config.node_name.clone(),
            stats: Some(stats),
        };
        let (_url, resp) = self
            .post_with_failover("/api/v1/nodes/heartbeat", &body)
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("hub heartbeat returned {}: {}", status, text);
        }
        Ok(())
    }

    /// 生成 Hub 鉴权头。
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.token)
    }

    /// 当前候选的 Hub URL。
    fn active_hub_url(&self) -> String {
        let idx = self.current_url_idx.load(Ordering::Relaxed);
        self.config
            .urls
            .get(idx)
            .cloned()
            .unwrap_or_else(|| self.config.urls.first().cloned().unwrap_or_else(|| "http://localhost:9930".to_string()))
            .trim_end_matches('/')
            .to_string()
    }

    /// 切换到下一个 Hub URL（主备故障转移）。
    fn rotate_hub_url(&self) {
        let next = (self.current_url_idx.load(Ordering::Relaxed) + 1) % self.config.urls.len();
        self.current_url_idx.store(next, Ordering::Relaxed);
    }

    /// 标记当前 Hub 可用，并把状态写回 ControlState 供 Dashboard 展示。
    fn mark_connected(&self, url: &str) {
        self.connected.store(true, Ordering::Relaxed);
        self.control
            .hub_connected
            .store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.control.hub_active_url.lock() {
            *guard = url.to_string();
        }
    }

    /// 标记所有 Hub 不可用，进入降级独立模式。
    fn mark_disconnected(&self) {
        self.connected.store(false, Ordering::Relaxed);
        self.control
            .hub_connected
            .store(false, Ordering::Relaxed);
    }

    /// 对 GET 请求尝试所有 Hub URL，直到成功或全部失败。
    async fn get_with_failover(&self, path: &str) -> Result<(String, reqwest::Response)> {
        let mut last_err = None;
        for _ in 0..self.config.urls.len() {
            let url = format!("{}{}", self.active_hub_url(), path);
            match self
                .http
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
                .await
            {
                Ok(resp) => {
                    self.mark_connected(&url);
                    return Ok((url, resp));
                }
                Err(e) => {
                    tracing::debug!("hub {} unreachable: {}", url, e);
                    last_err = Some(e);
                    self.rotate_hub_url();
                }
            }
        }
        self.mark_disconnected();
        Err(last_err
            .map(|e| anyhow::anyhow!("all hub URLs unreachable: {}", e))
            .unwrap_or_else(|| anyhow::anyhow!("no hub URL configured")))
    }

    /// 对 POST 请求尝试所有 Hub URL，直到成功或全部失败。
    async fn post_with_failover<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<(String, reqwest::Response)> {
        let mut last_err = None;
        for _ in 0..self.config.urls.len() {
            let url = format!("{}{}", self.active_hub_url(), path);
            match self
                .http
                .post(&url)
                .header("Authorization", self.auth_header())
                .json(body)
                .send()
                .await
            {
                Ok(resp) => {
                    self.mark_connected(&url);
                    return Ok((url, resp));
                }
                Err(e) => {
                    tracing::debug!("hub {} unreachable: {}", url, e);
                    last_err = Some(e);
                    self.rotate_hub_url();
                }
            }
        }
        self.mark_disconnected();
        Err(last_err
            .map(|e| anyhow::anyhow!("all hub URLs unreachable: {}", e))
            .unwrap_or_else(|| anyhow::anyhow!("no hub URL configured")))
    }
}

fn build_http_client(tls: &HubTlsConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(60));

    if tls.enabled {
        if !tls.verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(ca_path) = &tls.ca_cert {
            let ca = read_pem(ca_path)?;
            let cert = reqwest::Certificate::from_pem(&ca)
                .with_context(|| format!("failed to parse CA cert: {}", ca_path))?;
            builder = builder.add_root_certificate(cert);
        }
        if let (Some(cert_path), Some(key_path)) = (&tls.client_cert, &tls.client_key) {
            let cert = read_pem(cert_path)?;
            let key = read_pem(key_path)?;
            let mut combined = cert;
            combined.extend_from_slice(&key);
            let identity = reqwest::Identity::from_pem(&combined).with_context(|| {
                format!(
                    "failed to build client identity from {} and {}",
                    cert_path, key_path
                )
            })?;
            builder = builder.identity(identity);
        }
    } else {
        // 明确关闭 TLS 时：接受任意证书（仅用于测试或可信内网）
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder.build().context("failed to build reqwest client")
}

fn read_pem(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("failed to read PEM file: {}", path))
}

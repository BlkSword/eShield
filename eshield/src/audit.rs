use chrono::Utc;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 审计事件类型
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    BlockIp,
    UnblockIp,
    AllowCidr,
    DisallowCidr,
    ReloadConfig,
    PatchConfig,
    Start,
    Stop,
    ChallengePass,
}

/// 单条审计记录
#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub actor: String,
    pub action: AuditAction,
    pub detail: serde_json::Value,
    pub source_ip: Option<String>,
}

/// 审计日志后端 trait
#[async_trait::async_trait]
pub trait AuditBackend: Send + Sync {
    async fn append(&self, entry: AuditEntry) -> anyhow::Result<()>;
    async fn list(&self, limit: usize) -> anyhow::Result<Vec<AuditEntry>>;
}

/// 内存审计后端（适合测试与默认运行）
pub struct MemoryAuditBackend {
    entries: Mutex<Vec<AuditEntry>>,
    max_entries: usize,
}

impl MemoryAuditBackend {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            max_entries,
        }
    }
}

#[async_trait::async_trait]
impl AuditBackend for MemoryAuditBackend {
    async fn append(&self, entry: AuditEntry) -> anyhow::Result<()> {
        let mut guard = self.entries.lock().await;
        guard.push(entry);
        if guard.len() > self.max_entries {
            guard.remove(0);
        }
        Ok(())
    }

    async fn list(&self, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
        let guard = self.entries.lock().await;
        let start = guard.len().saturating_sub(limit);
        Ok(guard[start..].to_vec())
    }
}

/// 审计器：业务代码通过它记录操作。
#[derive(Clone)]
pub struct Auditor {
    backend: Arc<dyn AuditBackend>,
}

impl Auditor {
    pub fn new<B: AuditBackend + 'static>(backend: B) -> Self {
        Self {
            backend: Arc::new(backend),
        }
    }

    pub async fn log(
        &self,
        actor: impl Into<String>,
        action: AuditAction,
        detail: serde_json::Value,
        source_ip: Option<String>,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            actor: actor.into(),
            action,
            detail,
            source_ip,
        };
        if let Err(e) = self.backend.append(entry).await {
            tracing::warn!("audit log append failed: {}", e);
        }
    }

    pub async fn list(&self, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
        self.backend.list(limit).await
    }
}

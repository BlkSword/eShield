use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, Mutex};
use tracing::info;

/// 审计事件类型
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    Login,
    ResetToken,
}

/// 单条审计记录
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// 文件审计后端：将审计事件以 JSON Lines 形式持久化到磁盘。
///
/// - 每条事件独占一行，便于 `tail -f` 和日志采集器解析。
/// - 文件大小超过阈值后自动轮转，最多保留 3 个历史备份。
/// - 重启后历史审计记录仍然可查。
pub struct FileAuditBackend {
    path: PathBuf,
    max_size: u64,
    max_backups: u32,
    write_lock: Mutex<()>,
}

impl FileAuditBackend {
    pub fn new<P: AsRef<Path>>(path: P, max_size_mb: u64) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create audit log directory: {}", parent.display()))?;
            }
        }
        Ok(Self {
            path,
            max_size: max_size_mb.saturating_mul(1024 * 1024),
            max_backups: 3,
            write_lock: Mutex::new(()),
        })
    }

    async fn maybe_rotate(&self) -> anyhow::Result<()> {
        if self.max_size == 0 {
            return Ok(());
        }
        let meta = match fs::metadata(&self.path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if meta.len() <= self.max_size {
            return Ok(());
        }

        // 从旧到新轮转：audit.log.2 -> audit.log.3，audit.log.1 -> audit.log.2
        for i in (1..self.max_backups).rev() {
            let src = self.path.with_extension(format!("log.{}", i));
            let dst = self.path.with_extension(format!("log.{}", i + 1));
            if src.exists() {
                fs::rename(&src, &dst)
                    .await
                    .with_context(|| format!("rotate {} -> {}", src.display(), dst.display()))?;
            }
        }

        let first_backup = self.path.with_extension("log.1");
        fs::rename(&self.path, &first_backup)
            .await
            .with_context(|| format!("rotate {} -> {}", self.path.display(), first_backup.display()))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuditBackend for FileAuditBackend {
    async fn append(&self, entry: AuditEntry) -> anyhow::Result<()> {
        let line = serde_json::to_string(&entry)?;

        let _guard = self.write_lock.lock().await;

        self.maybe_rotate().await?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .with_context(|| format!("cannot open audit log: {}", self.path.display()))?;

        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;

        Ok(())
    }

    async fn list(&self, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(&self.path)
            .await
            .with_context(|| format!("cannot open audit log: {}", self.path.display()))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut entries = Vec::new();

        while let Some(line) = lines.next_line().await? {
            let line: String = line;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(e) => tracing::warn!("failed to parse audit log line: {}", e),
            }
        }

        let start = entries.len().saturating_sub(limit);
        Ok(entries[start..].to_vec())
    }
}

/// 审计器：业务代码通过它记录操作。
#[derive(Clone)]
pub struct Auditor {
    backend: Arc<dyn AuditBackend>,
    tx: broadcast::Sender<AuditEntry>,
}

impl Auditor {
    pub fn new<B: AuditBackend + 'static>(backend: B) -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self {
            backend: Arc::new(backend),
            tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuditEntry> {
        self.tx.subscribe()
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
            action: action.clone(),
            detail: detail.clone(),
            source_ip: source_ip.clone(),
        };

        info!(
            event_type = "audit",
            actor = entry.actor,
            action = format!("{:?}", entry.action),
            source_ip = entry.source_ip.as_deref().unwrap_or(""),
            detail = %entry.detail,
            "audit event"
        );

        let _ = self.tx.send(entry.clone());

        if let Err(e) = self.backend.append(entry).await {
            tracing::warn!("audit log append failed: {}", e);
        }
    }

    pub async fn list(&self, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
        self.backend.list(limit).await
    }
}

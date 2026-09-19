use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
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
    entries: Mutex<VecDeque<AuditEntry>>,
    max_entries: usize,
}

impl MemoryAuditBackend {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
            max_entries,
        }
    }
}

#[async_trait::async_trait]
impl AuditBackend for MemoryAuditBackend {
    async fn append(&self, entry: AuditEntry) -> anyhow::Result<()> {
        let mut guard = self.entries.lock().await;
        guard.push_back(entry);
        while guard.len() > self.max_entries {
            guard.pop_front();
        }
        Ok(())
    }

    async fn list(&self, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
        let guard = self.entries.lock().await;
        Ok(guard.iter().rev().take(limit).rev().cloned().collect())
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
    /// 复用的追加句柄；轮转或外部替换文件后自动重开。
    file: Mutex<Option<tokio::fs::File>>,
}

impl FileAuditBackend {
    pub fn new<P: AsRef<Path>>(path: P, max_size_mb: u64) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("cannot create audit log directory: {}", parent.display())
                })?;
            }
        }
        Ok(Self {
            path,
            max_size: max_size_mb.saturating_mul(1024 * 1024),
            max_backups: 3,
            write_lock: Mutex::new(()),
            file: Mutex::new(None),
        })
    }

    async fn maybe_rotate(&self) -> anyhow::Result<bool> {
        if self.max_size == 0 {
            return Ok(false);
        }
        let meta = match fs::metadata(&self.path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if meta.len() <= self.max_size {
            return Ok(false);
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
            .with_context(|| {
                format!(
                    "rotate {} -> {}",
                    self.path.display(),
                    first_backup.display()
                )
            })?;
        Ok(true)
    }
}

#[async_trait::async_trait]
impl AuditBackend for FileAuditBackend {
    async fn append(&self, entry: AuditEntry) -> anyhow::Result<()> {
        let line = serde_json::to_string(&entry)?;

        let _guard = self.write_lock.lock().await;
        let rotated = self.maybe_rotate().await?;

        let mut file_guard = self.file.lock().await;
        let need_open = rotated
            || match file_guard.as_ref() {
                None => true,
                Some(file) => match (file.metadata().await, fs::metadata(&self.path).await) {
                    (Ok(open_meta), Ok(path_meta)) => open_meta.ino() != path_meta.ino(),
                    _ => true,
                },
            };
        if need_open {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .await
                .with_context(|| format!("cannot open audit log: {}", self.path.display()))?;
            *file_guard = Some(file);
        }

        let file = file_guard
            .as_mut()
            .expect("audit file handle must be initialized");
        file.write_all(line.as_bytes()).await?;
        file.write_all(
            b"
",
        )
        .await?;
        file.flush().await?;

        Ok(())
    }

    async fn list(&self, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || list_tail(&path, limit))
            .await
            .context("audit list task panicked")?
    }
}

/// 从 JSON Lines 审计文件尾部读取最近 `limit` 条，避免每次请求都全量读盘。
fn list_tail(path: &Path, limit: usize) -> anyhow::Result<Vec<AuditEntry>> {
    if limit == 0 || !path.exists() {
        return Ok(Vec::new());
    }
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("cannot open audit log: {}", path.display()))?;
    let file_len = file.metadata()?.len();
    const CHUNK: u64 = 64 * 1024;

    let mut pos = file_len;
    let mut newlines = 0usize;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    while pos > 0 && newlines < limit + 1 {
        let read_len = CHUNK.min(pos);
        pos -= read_len;
        file.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; read_len as usize];
        file.read_exact(&mut buf)?;
        newlines += buf.iter().filter(|&&b| b == b'\n').count();
        chunks.push(buf);
    }
    chunks.reverse();
    let mut data = Vec::with_capacity(chunks.iter().map(|c| c.len()).sum());
    for chunk in chunks {
        data.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&data);

    let mut entries: VecDeque<AuditEntry> = VecDeque::with_capacity(limit.min(1024));
    for line in text.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(entry) => {
                entries.push_front(entry);
                if entries.len() >= limit {
                    break;
                }
            }
            Err(e) => tracing::warn!("failed to parse audit log line: {}", e),
        }
    }
    Ok(entries.into_iter().collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn entry(actor: &str) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            actor: actor.to_string(),
            action: AuditAction::BlockIp,
            detail: serde_json::json!({}),
            source_ip: None,
        }
    }

    #[tokio::test]
    async fn memory_backend_keeps_last_n() {
        let backend = MemoryAuditBackend::new(2);
        for name in ["a", "b", "c"] {
            backend.append(entry(name)).await.unwrap();
        }
        let listed = backend.list(10).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].actor, "b");
        assert_eq!(listed[1].actor, "c");
    }

    #[tokio::test]
    async fn file_backend_reads_tail() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let backend = FileAuditBackend::new(&path, 0).unwrap();
        for name in ["a", "b", "c", "d"] {
            backend.append(entry(name)).await.unwrap();
        }
        let listed = backend.list(2).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].actor, "c");
        assert_eq!(listed[1].actor, "d");
    }
}

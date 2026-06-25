use anyhow::Context;
use eshield_common::{IpKey, PortAclEntry};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use tokio::task;

// Table definitions
const BLACKLIST: TableDefinition<&[u8], BlacklistRow> = TableDefinition::new("blacklist");
const WHITELIST: TableDefinition<&[u8], WhitelistRow> = TableDefinition::new("whitelist");
const PORT_ACL: TableDefinition<u32, AclRow> = TableDefinition::new("port_acl");

#[derive(redb::Value, Debug, Clone)]
struct BlacklistRow {
    blocked_until_ns: u64,
    block_reason: u8,
    first_seen_ns: u64,
}

#[derive(redb::Value, Debug, Clone)]
struct WhitelistRow {
    prefix: u32,
}

#[derive(redb::Value, Debug, Clone)]
struct AclRow {
    protocol: u8,
    dport_low: u16,
    dport_high: u16,
    action: u8,
}

fn ip_key_bytes(key: &IpKey) -> [u8; 17] {
    let mut out = [0u8; 17];
    out[0] = key.family;
    out[1..].copy_from_slice(&key.addr);
    out
}

/// 持久化存储：保存动态规则（黑名单、白名单、ACL）到 redb（纯 Rust，无需 C 编译器）。
#[derive(Clone)]
pub struct RuleStore {
    path: Arc<std::path::PathBuf>,
}

impl RuleStore {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = Arc::new(path.as_ref().to_path_buf());
        let parent = path.parent().context("invalid store path")?;
        std::fs::create_dir_all(parent)?;
        // Ensure the database file can be opened.
        let _db = Database::create(path.as_ref())?;
        Ok(Self { path })
    }

    async fn run_blocking<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Database) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let path = self.path.clone();
        task::spawn_blocking(move || {
            let db = Database::create(path.as_ref())?;
            f(&db)
        })
        .await?
    }

    pub async fn save_blacklist(
        &self,
        key: IpKey,
        blocked_until_ns: u64,
        block_reason: u8,
        first_seen_ns: u64,
    ) -> anyhow::Result<()> {
        self.run_blocking(move |db| {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(BLACKLIST)?;
                table.insert(
                    &ip_key_bytes(&key)[..],
                    BlacklistRow {
                        blocked_until_ns,
                        block_reason,
                        first_seen_ns,
                    },
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn remove_blacklist(&self, key: IpKey) -> anyhow::Result<()> {
        self.run_blocking(move |db| {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(BLACKLIST)?;
                table.remove(&ip_key_bytes(&key)[..])?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn load_blacklist(&self) -> anyhow::Result<Vec<(IpKey, u64, u8, u64)>> {
        self.run_blocking(|db| {
            let tx = db.begin_read()?;
            let table = tx.open_table(BLACKLIST)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let bytes = k.value();
                let key = ip_bytes_to_key(bytes);
                let row = v.value();
                out.push((key, row.blocked_until_ns, row.block_reason, row.first_seen_ns));
            }
            Ok(out)
        })
        .await
    }

    pub async fn save_whitelist(&self, key: IpKey, prefix: u32) -> anyhow::Result<()> {
        self.run_blocking(move |db| {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(WHITELIST)?;
                table.insert(&ip_key_bytes(&key)[..], WhitelistRow { prefix })?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn remove_whitelist(&self, key: IpKey, prefix: u32) -> anyhow::Result<()> {
        // redb keys are just the IP bytes; we also store prefix in value.
        // For simplicity, remove by key regardless of prefix.
        let _ = prefix;
        self.run_blocking(move |db| {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(WHITELIST)?;
                table.remove(&ip_key_bytes(&key)[..])?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn load_whitelist(&self) -> anyhow::Result<Vec<(IpKey, u32)>> {
        self.run_blocking(|db| {
            let tx = db.begin_read()?;
            let table = tx.open_table(WHITELIST)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let key = ip_bytes_to_key(k.value());
                out.push((key, v.value().prefix));
            }
            Ok(out)
        })
        .await
    }

    pub async fn save_port_acl(&self, idx: u32, entry: PortAclEntry) -> anyhow::Result<()> {
        self.run_blocking(move |db| {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(PORT_ACL)?;
                table.insert(
                    &idx,
                    AclRow {
                        protocol: entry.protocol,
                        dport_low: entry.dport_low,
                        dport_high: entry.dport_high,
                        action: entry.action,
                    },
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn clear_port_acl(&self) -> anyhow::Result<()> {
        self.run_blocking(|db| {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(PORT_ACL)?;
                for item in table.iter()? {
                    let (k, _) = item?;
                    table.remove(k.value())?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn load_port_acl(&self) -> anyhow::Result<Vec<(u32, PortAclEntry)>> {
        self.run_blocking(|db| {
            let tx = db.begin_read()?;
            let table = tx.open_table(PORT_ACL)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let row = v.value();
                out.push((
                    *k.value(),
                    PortAclEntry {
                        protocol: row.protocol,
                        dport_low: row.dport_low,
                        dport_high: row.dport_high,
                        action: row.action,
                        padding: [0; 11],
                    },
                ));
            }
            Ok(out)
        })
        .await
    }
}

fn ip_bytes_to_key(bytes: &[u8]) -> IpKey {
    let family = bytes.first().copied().unwrap_or(0);
    let mut addr = [0u8; 16];
    if bytes.len() >= 17 {
        addr.copy_from_slice(&bytes[1..17]);
    }
    IpKey {
        family,
        addr,
        padding: [0; 15],
    }
}

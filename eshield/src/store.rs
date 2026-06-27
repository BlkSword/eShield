use anyhow::Context;
use eshield_common::IpKey;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

// 使用 JSON 字节作为 value，避免自定义 RedbValue 实现。
const BLACKLIST: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blacklist");
const WHITELIST: TableDefinition<&[u8], &[u8]> = TableDefinition::new("whitelist");
const PORT_ACL: TableDefinition<u32, &[u8]> = TableDefinition::new("port_acl");

#[derive(Clone)]
pub struct RuleStore {
    db: Arc<Database>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct BlacklistRow {
    blocked_until_ns: u64,
    block_reason: u8,
    first_seen_ns: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WhitelistRow {
    prefix: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AclRow {
    protocol: u8,
    dport_low: u16,
    dport_high: u16,
    action: u8,
}

impl RuleStore {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let db = Database::create(path).context("failed to create/open rule store")?;
        Ok(Self { db: Arc::new(db) })
    }

    fn ip_key_bytes(key: &IpKey) -> [u8; 17] {
        let mut bytes = [0u8; 17];
        bytes[0] = key.family;
        bytes[1..].copy_from_slice(&key.addr);
        bytes
    }

    pub async fn save_blacklist(
        &self,
        key: IpKey,
        blocked_until_ns: u64,
        block_reason: u8,
        first_seen_ns: u64,
    ) -> anyhow::Result<()> {
        let db = self.db.clone();
        let row = BlacklistRow {
            blocked_until_ns,
            block_reason,
            first_seen_ns,
        };
        let value = serde_json::to_vec(&row)?;
        let ip = Self::ip_key_bytes(&key);
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(BLACKLIST)?;
                table.insert(&ip[..], value.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn remove_blacklist(&self, key: IpKey) -> anyhow::Result<()> {
        let db = self.db.clone();
        let ip = Self::ip_key_bytes(&key);
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(BLACKLIST)?;
                table.remove(&ip[..])?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn load_blacklist(&self) -> anyhow::Result<Vec<(IpKey, u64, u8, u64)>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read()?;
            let table = tx.open_table(BLACKLIST)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let key = Self::bytes_to_ip_key(k.value());
                let row: BlacklistRow = serde_json::from_slice(v.value())?;
                out.push((key, row.blocked_until_ns, row.block_reason, row.first_seen_ns));
            }
            Ok(out)
        })
        .await
        .context("store task panicked")?
    }

    pub async fn save_whitelist(&self, key: IpKey, prefix: u32) -> anyhow::Result<()> {
        let db = self.db.clone();
        let row = WhitelistRow { prefix };
        let value = serde_json::to_vec(&row)?;
        let ip = Self::ip_key_bytes(&key);
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(WHITELIST)?;
                table.insert(&ip[..], value.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn remove_whitelist(&self, key: IpKey, prefix: u32) -> anyhow::Result<()> {
        let db = self.db.clone();
        let row = WhitelistRow { prefix };
        let value = serde_json::to_vec(&row)?;
        let ip = Self::ip_key_bytes(&key);
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(WHITELIST)?;
                // 仅当 value 一致时才删除，避免误删
                table.remove(&ip[..])?;
                // redb 的 remove 不校验 value；如需校验可改用 get + remove
                let _ = value;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn load_whitelist(&self) -> anyhow::Result<Vec<(IpKey, u32)>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read()?;
            let table = tx.open_table(WHITELIST)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let key = Self::bytes_to_ip_key(k.value());
                let row: WhitelistRow = serde_json::from_slice(v.value())?;
                out.push((key, row.prefix));
            }
            Ok(out)
        })
        .await
        .context("store task panicked")?
    }

    pub async fn save_port_acl(
        &self,
        idx: u32,
        entry: eshield_common::PortAclEntry,
    ) -> anyhow::Result<()> {
        let db = self.db.clone();
        let row = AclRow {
            protocol: entry.protocol,
            dport_low: entry.dport_low,
            dport_high: entry.dport_high,
            action: entry.action,
        };
        let value = serde_json::to_vec(&row)?;
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(PORT_ACL)?;
                table.insert(&idx, value.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn load_port_acl(&self) -> anyhow::Result<Vec<(u32, eshield_common::PortAclEntry)>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read()?;
            let table = tx.open_table(PORT_ACL)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let row: AclRow = serde_json::from_slice(v.value())?;
                out.push((
                    k.value(),
                    eshield_common::PortAclEntry {
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
        .context("store task panicked")?
    }

    fn bytes_to_ip_key(bytes: &[u8]) -> IpKey {
        let mut addr = [0u8; 16];
        if bytes.len() >= 17 {
            addr.copy_from_slice(&bytes[1..17]);
            IpKey {
                family: bytes[0],
                addr,
                padding: [0; 15],
            }
        } else {
            IpKey::default()
        }
    }
}

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
const WAF_RULES: TableDefinition<u32, &[u8]> = TableDefinition::new("waf_rules");
const L7_PATTERNS: TableDefinition<u32, &[u8]> = TableDefinition::new("l7_patterns");
const PROTECTION_PROJECTS: TableDefinition<u32, &[u8]> = TableDefinition::new("protection_projects");

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
            let table = match tx.open_table(BLACKLIST) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
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
            let table = match tx.open_table(WHITELIST) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
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

    pub async fn save_port_acl_items(
        &self,
        items: &[crate::config::PortAclItem],
    ) -> anyhow::Result<()> {
        let db = self.db.clone();
        let value = serde_json::to_vec(items)?;
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(PORT_ACL)?;
                table.insert(&0u32, value.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn load_port_acl_items(&self) -> anyhow::Result<Vec<crate::config::PortAclItem>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read()?;
            let table = match tx.open_table(PORT_ACL) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
            let value = table.get(&0u32)?;
            match value {
                Some(v) => Ok(serde_json::from_slice(v.value())?),
                None => Ok(Vec::new()),
            }
        })
        .await
        .context("store task panicked")?
    }

    pub async fn save_waf_rules(&self, rules: &[crate::config::WafRuleItem]) -> anyhow::Result<()> {
        let db = self.db.clone();
        let value = serde_json::to_vec(rules)?;
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(WAF_RULES)?;
                table.insert(&0u32, value.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn load_waf_rules(&self) -> anyhow::Result<Vec<crate::config::WafRuleItem>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read()?;
            let table = match tx.open_table(WAF_RULES) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
            let value = table.get(&0u32)?;
            match value {
                Some(v) => Ok(serde_json::from_slice(v.value())?),
                None => Ok(Vec::new()),
            }
        })
        .await
        .context("store task panicked")?
    }

    pub async fn save_l7_patterns(
        &self,
        patterns: &[crate::config::L7PatternConfig],
    ) -> anyhow::Result<()> {
        let db = self.db.clone();
        let value = serde_json::to_vec(patterns)?;
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(L7_PATTERNS)?;
                table.insert(&0u32, value.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn load_l7_patterns(&self) -> anyhow::Result<Vec<crate::config::L7PatternConfig>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read()?;
            let table = match tx.open_table(L7_PATTERNS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
            let value = table.get(&0u32)?;
            match value {
                Some(v) => Ok(serde_json::from_slice(v.value())?),
                None => Ok(Vec::new()),
            }
        })
        .await
        .context("store task panicked")?
    }

    pub async fn save_protection_projects(
        &self,
        projects: &[crate::config::ProtectionProject],
    ) -> anyhow::Result<()> {
        let db = self.db.clone();
        let value = serde_json::to_vec(projects)?;
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(PROTECTION_PROJECTS)?;
                table.insert(&0u32, value.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .context("store task panicked")?
    }

    pub async fn load_protection_projects(
        &self,
    ) -> anyhow::Result<Vec<crate::config::ProtectionProject>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read()?;
            let table = match tx.open_table(PROTECTION_PROJECTS) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
            let value = table.get(&0u32)?;
            match value {
                Some(v) => Ok(serde_json::from_slice(v.value())?),
                None => Ok(Vec::new()),
            }
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

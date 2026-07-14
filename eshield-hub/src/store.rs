use crate::models::{NodePolicy, SharedPolicy};
use crate::time::now_ns;
use anyhow::{Context, Result};
use eshield_common::IpKey;
use redb::{Database, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;

const POLICIES_TABLE: TableDefinition<&[u8; 25], &[u8]> = TableDefinition::new("policies");
const TOMBSTONES_TABLE: TableDefinition<&[u8; 25], &[u8]> = TableDefinition::new("tombstones");
const RULES_TABLE: TableDefinition<u32, &[u8]> = TableDefinition::new("rules");

use crate::models::RuleBundle;

fn composite_key(last_seen_ns: u64, ip: &IpKey) -> [u8; 25] {
    let mut key = [0u8; 25];
    key[0..8].copy_from_slice(&last_seen_ns.to_be_bytes());
    key[8] = ip.family;
    key[9..25].copy_from_slice(&ip.addr);
    key
}

pub struct Store {
    db: Database,
}

impl Store {
    pub fn new(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        Ok(Self { db })
    }

    pub fn merge(&self, node_name: &str, policies: &[NodePolicy]) -> Result<usize> {
        let now_ns = now_ns();
        let write_txn = self.db.begin_write()?;
        let mut merged = 0usize;
        {
            let mut table = write_txn
                .open_table(POLICIES_TABLE)
                .context("open policies table")?;

            // Load current persisted state keyed by IP so we can merge in memory.
            let mut existing: HashMap<IpKey, (SharedPolicy, [u8; 25])> = HashMap::new();
            for result in table.iter()? {
                let (k, v) = result?;
                let key = k.value();
                let policy: SharedPolicy =
                    serde_json::from_slice(v.value()).context("deserialize stored policy")?;
                existing.insert(policy.ip, (policy, *key));
            }

            for node in policies {
                let (policy, old_key) =
                    if let Some((existing_policy, old_key)) = existing.remove(&node.ip) {
                        let mut p = existing_policy;
                        p.reason = node.reason;
                        p.hit_count = p.hit_count.max(node.hit_count);
                        p.trust_score = p.trust_score.min(node.trust_score);
                        if !p.source_nodes.iter().any(|s| s == node_name) {
                            p.source_nodes.push(node_name.to_string());
                        }
                        p.ttl_s = p.ttl_s.max(node.ttl_s);
                        p.last_seen_ns = p.last_seen_ns.max(now_ns);
                        p.first_seen_ns = p.first_seen_ns.min(now_ns);
                        (p, Some(old_key))
                    } else {
                        let p = SharedPolicy {
                            ip: node.ip,
                            reason: node.reason,
                            hit_count: node.hit_count,
                            trust_score: node.trust_score,
                            first_seen_ns: now_ns,
                            last_seen_ns: now_ns,
                            source_nodes: vec![node_name.to_string()],
                            ttl_s: node.ttl_s,
                        };
                        (p, None)
                    };

                let new_key = composite_key(policy.last_seen_ns, &policy.ip);
                if let Some(old_key) = old_key {
                    if old_key != new_key {
                        table.remove(&old_key)?;
                    }
                }

                let bytes = serde_json::to_vec(&policy).context("serialize policy")?;
                table.insert(&new_key, bytes.as_slice())?;
                existing.insert(policy.ip, (policy, new_key));
                merged += 1;
            }
        }
        write_txn.commit()?;
        Ok(merged)
    }

    pub fn query_since(&self, since_ns: u64, limit: usize) -> Result<(Vec<SharedPolicy>, u64)> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(POLICIES_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok((Vec::new(), since_ns)),
            Err(e) => return Err(e.into()),
        };

        let mut policies = Vec::new();
        let mut cursor = since_ns;

        for result in table.iter()? {
            let (k, v) = result?;
            let key = k.value();
            let last_seen_ns = u64::from_be_bytes(key[0..8].try_into().unwrap());

            if last_seen_ns > since_ns {
                let policy: SharedPolicy = serde_json::from_slice(v.value())?;
                policies.push(policy);
                cursor = cursor.max(last_seen_ns);
            }
        }

        policies.truncate(limit);
        Ok((policies, cursor))
    }

    pub fn count(&self) -> Result<u64> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(POLICIES_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        Ok(table.len()?)
    }

    /// 从策略库中删除指定 IP，并写入 tombstone，供下游节点同步解封。
    pub fn delete_policy(&self, ip: &IpKey) -> Result<bool> {
        let now_ns = now_ns();
        let write_txn = self.db.begin_write()?;

        let mut policies = write_txn.open_table(POLICIES_TABLE)?;
        let mut removed = false;
        // 按 IP 查找并删除现有策略（ policies 表按键是复合键，需遍历匹配）。
        let mut to_remove = Vec::new();
        for result in policies.iter()? {
            let (k, v) = result?;
            let stored: SharedPolicy = serde_json::from_slice(v.value())?;
            if stored.ip == *ip {
                to_remove.push(*k.value());
            }
        }
        for key in to_remove {
            policies.remove(&key)?;
            removed = true;
        }
        drop(policies);

        let mut tombstones = write_txn.open_table(TOMBSTONES_TABLE)?;
        let tkey = composite_key(now_ns, ip);
        tombstones.insert(&tkey, &[] as &[u8])?;
        drop(tombstones);

        write_txn.commit()?;
        Ok(removed)
    }

    /// 查询自 `since_ns` 以来被删除的策略。
    pub fn query_tombstones_since(&self, since_ns: u64, limit: usize) -> Result<(Vec<IpKey>, u64)> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(TOMBSTONES_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok((Vec::new(), since_ns)),
            Err(e) => return Err(e.into()),
        };

        let mut ips = Vec::new();
        let mut cursor = since_ns;
        for result in table.iter()? {
            let (k, _) = result?;
            let key = k.value();
            let deleted_at = u64::from_be_bytes(key[0..8].try_into().unwrap());
            if deleted_at > since_ns {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&key[9..25]);
                ips.push(IpKey {
                    family: key[8],
                    addr,
                    padding: [0; 15],
                });
                cursor = cursor.max(deleted_at);
            }
        }
        ips.truncate(limit);
        Ok((ips, cursor))
    }

    /// 保存 Hub 统一下发的规则包。
    pub fn set_rules(&self, bundle: &RuleBundle) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(RULES_TABLE)?;
            let bytes = serde_json::to_vec(bundle)?;
            table.insert(&0u32, bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// 读取当前 Hub 统一下发的规则包。
    pub fn get_rules(&self) -> Result<Option<RuleBundle>> {
        let read_txn = self.db.begin_read()?;
        let result = {
            let table = match read_txn.open_table(RULES_TABLE) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let value = table.get(&0u32)?;
            match value {
                Some(v) => Some(serde_json::from_slice(v.value())?),
                None => None,
            }
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NodePolicy;
    use eshield_common::IpKey;
    use tempfile::NamedTempFile;

    fn tmp_store() -> (Store, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let store = Store::new(file.path()).unwrap();
        (store, file)
    }

    #[test]
    fn merge_combines_policies() {
        let (store, _file) = tmp_store();
        let ip = IpKey::from_ipv4([192, 168, 1, 1]);

        let node1 = vec![NodePolicy {
            ip,
            reason: 1,
            hit_count: 10,
            trust_score: 500,
            blocked_until_ns: 0,
            ttl_s: 60,
        }];
        let node2 = vec![NodePolicy {
            ip,
            reason: 2,
            hit_count: 20,
            trust_score: 300,
            blocked_until_ns: 0,
            ttl_s: 120,
        }];

        assert_eq!(store.merge("node1", &node1).unwrap(), 1);
        assert_eq!(store.merge("node2", &node2).unwrap(), 1);

        let (policies, _cursor) = store.query_since(0, 10).unwrap();
        assert_eq!(policies.len(), 1);
        let p = &policies[0];
        assert_eq!(p.hit_count, 20);
        assert_eq!(p.trust_score, 300);
        assert!(p.source_nodes.contains(&"node1".to_string()));
        assert!(p.source_nodes.contains(&"node2".to_string()));
        assert_eq!(p.ttl_s, 120);
    }

    #[test]
    fn query_since_and_count() {
        let (store, _file) = tmp_store();
        let ip_a = IpKey::from_ipv4([10, 0, 0, 1]);
        let ip_b = IpKey::from_ipv4([10, 0, 0, 2]);

        store
            .merge(
                "node-a",
                &[
                    NodePolicy {
                        ip: ip_a,
                        reason: 1,
                        hit_count: 1,
                        trust_score: 100,
                        blocked_until_ns: 0,
                        ttl_s: 10,
                    },
                    NodePolicy {
                        ip: ip_b,
                        reason: 2,
                        hit_count: 1,
                        trust_score: 200,
                        blocked_until_ns: 0,
                        ttl_s: 10,
                    },
                ],
            )
            .unwrap();

        assert_eq!(store.count().unwrap(), 2);

        let (policies, cursor) = store.query_since(0, 1).unwrap();
        assert_eq!(policies.len(), 1);
        assert!(cursor >= policies[0].last_seen_ns);

        let (all, _cursor) = store.query_since(0, 100).unwrap();
        assert_eq!(all.len(), 2);
    }
}

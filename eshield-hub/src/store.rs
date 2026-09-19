use crate::models::{NodePolicy, SharedPolicy};
use crate::time::now_ns;
use anyhow::{Context, Result};
use eshield_common::IpKey;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;

const POLICIES_TABLE: TableDefinition<&[u8; 25], &[u8]> = TableDefinition::new("policies");
/// 源 IP -> 当前复合键的二级索引，避免每次 push 全量扫描策略表。
const POLICY_INDEX_TABLE: TableDefinition<&[u8; 17], &[u8; 25]> =
    TableDefinition::new("policy_index");
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

fn ip_index_key(ip: &IpKey) -> [u8; 17] {
    let mut key = [0u8; 17];
    key[0] = ip.family;
    key[1..].copy_from_slice(&ip.addr);
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
            let mut index = write_txn
                .open_table(POLICY_INDEX_TABLE)
                .context("open policy index table")?;

            // 旧库迁移：index 为空但已有策略时，先重建一次 IP -> 复合键索引。
            if index.len()? == 0 && table.len()? > 0 {
                let mut rebuilt: Vec<([u8; 17], [u8; 25])> = Vec::new();
                for item in table.iter()? {
                    let (k, v) = item?;
                    let policy: SharedPolicy =
                        serde_json::from_slice(v.value()).context("deserialize stored policy")?;
                    rebuilt.push((ip_index_key(&policy.ip), *k.value()));
                }
                for (index_key, composite) in rebuilt {
                    index.insert(&index_key, &composite)?;
                }
            }

            for node in policies {
                let index_key = ip_index_key(&node.ip);
                let old_key = index.get(&index_key)?.map(|v| *v.value());

                let policy = match old_key {
                    Some(composite) => {
                        let value = table
                            .get(&composite)?
                            .context("policy index points to missing row")?;
                        let mut p: SharedPolicy =
                            serde_json::from_slice(value.value()).context("deserialize policy")?;
                        p.reason = node.reason;
                        p.hit_count = p.hit_count.max(node.hit_count);
                        p.trust_score = p.trust_score.min(node.trust_score);
                        if !p.source_nodes.iter().any(|s| s == node_name) {
                            p.source_nodes.push(node_name.to_string());
                        }
                        // 0 表示永久封禁，不能被较短的 TTL 降级覆盖。
                        p.ttl_s = if p.ttl_s == 0 || node.ttl_s == 0 {
                            0
                        } else {
                            p.ttl_s.max(node.ttl_s)
                        };
                        p.last_seen_ns = p.last_seen_ns.max(now_ns);
                        p.first_seen_ns = p.first_seen_ns.min(now_ns);
                        p
                    }
                    None => SharedPolicy {
                        ip: node.ip,
                        reason: node.reason,
                        hit_count: node.hit_count,
                        trust_score: node.trust_score,
                        first_seen_ns: now_ns,
                        last_seen_ns: now_ns,
                        source_nodes: vec![node_name.to_string()],
                        ttl_s: node.ttl_s,
                    },
                };

                let new_key = composite_key(policy.last_seen_ns, &policy.ip);
                if let Some(old_key) = old_key {
                    if old_key != new_key {
                        table.remove(&old_key)?;
                    }
                }

                let bytes = serde_json::to_vec(&policy).context("serialize policy")?;
                table.insert(&new_key, bytes.as_slice())?;
                index.insert(&index_key, &new_key)?;
                merged += 1;
            }
        }
        write_txn.commit()?;
        Ok(merged)
    }

    /// 按键序增量查询策略。
    ///
    /// 复合键按 `(last_seen_ns, family, addr)` 升序排列。分页时不能简单
    /// `truncate(limit)` 后把游标推到全局最大值，否则被截断的条目永远不会再返回。
    /// 这里按“时间戳分组”分页：返回满 limit 条后，把同 `last_seen_ns` 的剩余条目
    /// 一并返回，游标只推进到该时间戳；下一轮用 `>` 即可继续，不会丢也不会重复。
    pub fn query_since(&self, since_ns: u64, limit: usize) -> Result<(Vec<SharedPolicy>, u64)> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(POLICIES_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok((Vec::new(), since_ns)),
            Err(e) => return Err(e.into()),
        };

        let mut policies = Vec::new();
        let mut cursor = since_ns;
        if limit == 0 {
            return Ok((policies, cursor));
        }

        let mut cutoff: Option<u64> = None;
        for result in table.iter()? {
            let (k, v) = result?;
            let key = k.value();
            let last_seen_ns = u64::from_be_bytes(key[0..8].try_into().unwrap());
            if last_seen_ns <= since_ns {
                continue;
            }

            if let Some(cutoff_ts) = cutoff {
                if last_seen_ns != cutoff_ts {
                    break;
                }
            } else if policies.len() >= limit {
                // 已攒满 limit，仍需把与最后一条同时间戳的剩余条目带上。
                cutoff = Some(last_seen_ns);
            }

            let policy: SharedPolicy = serde_json::from_slice(v.value())?;
            policies.push(policy);
            cursor = last_seen_ns;
        }

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

    /// 清理过期策略与 tombstone。
    ///
    /// - `ttl_s == 0` 视为永久策略，不清理；
    /// - 普通策略在 `last_seen_ns + ttl_s` 之后删除；
    /// - tombstone 保留 `tombstone_ttl_ns`，确保所有节点至少有机会拉到一次解封。
    pub fn prune(&self, now_ns: u64, tombstone_ttl_ns: u64) -> Result<(usize, usize)> {
        let write_txn = self.db.begin_write()?;
        let (policies_removed, tombstones_removed);
        {
            let mut policies = write_txn.open_table(POLICIES_TABLE)?;
            let mut index = write_txn.open_table(POLICY_INDEX_TABLE)?;
            let mut stale = Vec::new();
            for result in policies.iter()? {
                let (k, v) = result?;
                let policy: SharedPolicy = serde_json::from_slice(v.value())?;
                if policy.ttl_s != 0 {
                    let expire_at = policy
                        .last_seen_ns
                        .saturating_add(policy.ttl_s.saturating_mul(1_000_000_000));
                    if expire_at < now_ns {
                        stale.push((*k.value(), policy.ip));
                    }
                }
            }
            policies_removed = stale.len();
            for (key, ip) in stale {
                policies.remove(&key)?;
                index.remove(&ip_index_key(&ip))?;
            }
        }
        {
            let mut tombstones = write_txn.open_table(TOMBSTONES_TABLE)?;
            let mut stale = Vec::new();
            for result in tombstones.iter()? {
                let (k, _) = result?;
                let key = k.value();
                let deleted_at = u64::from_be_bytes(key[0..8].try_into().unwrap());
                if deleted_at.saturating_add(tombstone_ttl_ns) < now_ns {
                    stale.push(*key);
                }
            }
            tombstones_removed = stale.len();
            for key in stale {
                tombstones.remove(&key)?;
            }
        }
        write_txn.commit()?;
        Ok((policies_removed, tombstones_removed))
    }

    /// 从策略库中删除指定 IP，并写入 tombstone，供下游节点同步解封。
    pub fn delete_policy(&self, ip: &IpKey) -> Result<bool> {
        let now_ns = now_ns();
        let write_txn = self.db.begin_write()?;
        let mut removed = false;
        {
            let mut policies = write_txn.open_table(POLICIES_TABLE)?;
            let mut index = write_txn.open_table(POLICY_INDEX_TABLE)?;
            let index_key = ip_index_key(ip);

            let existing = {
                let guard = index.get(&index_key)?;
                guard.map(|v| *v.value())
            };
            match existing {
                Some(composite) => {
                    if policies.remove(&composite)?.is_some() {
                        removed = true;
                    }
                    index.remove(&index_key)?;
                }
                None => {
                    // 旧库没有索引时退化为一次扫描，并顺手补齐索引删除。
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
                    let _ = index.remove(&index_key);
                }
            }
        }

        let mut tombstones = write_txn.open_table(TOMBSTONES_TABLE)?;
        let tkey = composite_key(now_ns, ip);
        tombstones.insert(&tkey, &[] as &[u8])?;
        drop(tombstones);

        write_txn.commit()?;
        Ok(removed)
    }

    /// 查询自 `since_ns` 以来被删除的策略。
    /// 与 `query_since` 相同的按时间戳分组分页逻辑，用于 tombstone（解封）同步。
    pub fn query_tombstones_since(&self, since_ns: u64, limit: usize) -> Result<(Vec<IpKey>, u64)> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(TOMBSTONES_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok((Vec::new(), since_ns)),
            Err(e) => return Err(e.into()),
        };

        let mut ips = Vec::new();
        let mut cursor = since_ns;
        if limit == 0 {
            return Ok((ips, cursor));
        }
        let mut cutoff: Option<u64> = None;
        for result in table.iter()? {
            let (k, _) = result?;
            let key = k.value();
            let deleted_at = u64::from_be_bytes(key[0..8].try_into().unwrap());
            if deleted_at <= since_ns {
                continue;
            }
            if let Some(cutoff_ts) = cutoff {
                if deleted_at != cutoff_ts {
                    break;
                }
            } else if ips.len() >= limit {
                cutoff = Some(deleted_at);
            }

            let mut addr = [0u8; 16];
            addr.copy_from_slice(&key[9..25]);
            ips.push(IpKey {
                family: key[8],
                addr,
                padding: [0; 15],
            });
            cursor = deleted_at;
        }
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
        // 两条策略在同一次 merge 中写入，last_seen_ns 相同；按时间戳分组分页
        // 必须把同组条目一起返回，否则 limit 截断会永久丢策略。
        assert_eq!(policies.len(), 2);
        assert!(cursor >= policies[0].last_seen_ns);

        let (all, _cursor) = store.query_since(0, 100).unwrap();
        assert_eq!(all.len(), 2);
    }

    fn insert_policy_raw(store: &Store, ip: IpKey, last_seen_ns: u64, ttl_s: u64) {
        let policy = SharedPolicy {
            ip,
            reason: 1,
            hit_count: 1,
            trust_score: 100,
            first_seen_ns: last_seen_ns,
            last_seen_ns,
            source_nodes: vec!["test".to_string()],
            ttl_s,
        };
        let value = serde_json::to_vec(&policy).unwrap();
        let tx = store.db.begin_write().unwrap();
        {
            let mut table = tx.open_table(POLICIES_TABLE).unwrap();
            table
                .insert(&composite_key(last_seen_ns, &ip), value.as_slice())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    #[test]
    fn query_since_paginates_without_losing_same_timestamp_group() {
        let (store, _file) = tmp_store();
        insert_policy_raw(&store, IpKey::from_ipv4([10, 0, 0, 1]), 10, 3600);
        insert_policy_raw(&store, IpKey::from_ipv4([10, 0, 0, 2]), 20, 3600);
        insert_policy_raw(&store, IpKey::from_ipv4([10, 0, 0, 3]), 20, 3600);
        insert_policy_raw(&store, IpKey::from_ipv4([10, 0, 0, 4]), 20, 3600);
        insert_policy_raw(&store, IpKey::from_ipv4([10, 0, 0, 5]), 30, 3600);

        let (first, cursor) = store.query_since(0, 2).unwrap();
        // ts=10 一条 + limit 用满后同属 ts=20 的三条必须一起返回（共 4 条），
        // 下一轮从 cursor=20 继续，ts=30 的条目不会丢。
        assert_eq!(
            first.len(),
            4,
            "same-timestamp group must be returned together"
        );
        assert_eq!(cursor, 20);

        let (second, cursor2) = store.query_since(cursor, 2).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(cursor2, 30);
    }

    #[test]
    fn prune_removes_expired_policies_and_tombstones() {
        let (store, _file) = tmp_store();
        let now = 10_000_000_000_000u64;
        insert_policy_raw(
            &store,
            IpKey::from_ipv4([10, 0, 0, 1]),
            now - 2_000_000_000,
            1,
        );
        insert_policy_raw(&store, IpKey::from_ipv4([10, 0, 0, 2]), now, 0);
        let tx = store.db.begin_write().unwrap();
        {
            let mut table = tx.open_table(TOMBSTONES_TABLE).unwrap();
            let old_key = composite_key(now - 100_000_000_000, &IpKey::from_ipv4([10, 0, 0, 9]));
            table.insert(&old_key, &[] as &[u8]).unwrap();
        }
        tx.commit().unwrap();

        let (policies, tombstones) = store.prune(now, 60_000_000_000).unwrap();
        assert_eq!(policies, 1);
        assert_eq!(tombstones, 1);
        assert_eq!(store.count().unwrap(), 1);
    }
}

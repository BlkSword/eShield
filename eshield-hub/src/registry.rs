use crate::models::NodeInfo;
use crate::time::now_ns;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct NodeRegistry {
    nodes: DashMap<String, NodeInfo>,
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
        }
    }

    pub fn heartbeat(&self, name: String, now_ns: u64) {
        self.nodes.insert(
            name.clone(),
            NodeInfo {
                name,
                last_seen_ns: now_ns,
                online: true,
            },
        );
    }

    pub fn list(&self, now_ns: u64, timeout_ns: u64) -> Vec<NodeInfo> {
        self.nodes
            .iter()
            .map(|entry| {
                let mut info = entry.value().clone();
                info.online = now_ns.saturating_sub(info.last_seen_ns) <= timeout_ns;
                info
            })
            .collect()
    }

    /// Spawn a background task that removes nodes that have not been seen
    /// within `timeout_ns`. Online status is normally computed at query time;
    /// this task merely prunes stale entries.
    pub fn cleanup_task(self: Arc<Self>, timeout_ns: u64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = now_ns();
                self.nodes
                    .retain(|_, info| now.saturating_sub(info.last_seen_ns) <= timeout_ns);
            }
        });
    }
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

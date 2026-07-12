use crate::{auth::HubAuth, limiter::RateLimiter, registry::NodeRegistry, store::Store};
use std::sync::Arc;

pub struct AppState {
    pub store: Arc<Store>,
    pub registry: Arc<NodeRegistry>,
    pub auth: HubAuth,
    pub rate_limiter: RateLimiter,
    pub node_timeout_ns: u64,
}

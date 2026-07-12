mod api;
mod auth;
mod feed;
mod limiter;
mod models;
mod registry;
mod state;
mod store;
mod tls;

pub(crate) mod time {
    pub(crate) fn now_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

use crate::{
    auth::HubAuth, limiter::RateLimiter, registry::NodeRegistry, state::AppState, store::Store,
};
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "eshield-hub")]
#[command(about = "eShield distributed policy hub")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:9930")]
    bind: String,

    #[arg(long)]
    token: Option<String>,

    #[arg(long, default_value = "/var/lib/eshield-hub/policies.redb")]
    store_path: PathBuf,

    #[arg(long)]
    tls_cert: Option<PathBuf>,

    #[arg(long)]
    tls_key: Option<PathBuf>,

    #[arg(long)]
    tls_client_ca: Option<PathBuf>,

    #[arg(long, default_value_t = 120)]
    node_timeout_s: u64,

    /// 威胁情报 feed URL（Hub 统一拉取后分发给各节点）。
    #[arg(long)]
    threat_feed_url: Option<String>,

    #[arg(long, default_value_t = 3600)]
    threat_feed_interval_s: u64,

    #[arg(long, default_value = "drop")]
    threat_feed_action: String,

    #[arg(long, default_value_t = 86400)]
    threat_feed_ttl_s: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let token = args
        .token
        .or_else(|| std::env::var("ESHIELD_HUB_TOKEN").ok())
        .unwrap_or_default();
    if token.is_empty() {
        bail!("--token or ESHIELD_HUB_TOKEN is required");
    }

    if let Some(parent) = args.store_path.parent() {
        std::fs::create_dir_all(parent).context("create store directory")?;
    }

    let store = Arc::new(Store::new(&args.store_path).context("open policy store")?);
    let registry = NodeRegistry::new();
    let rate_limiter = RateLimiter::default();

    let registry = Arc::new(registry);
    registry
        .clone()
        .cleanup_task(args.node_timeout_s * 1_000_000_000);

    if let Some(feed_url) = args.threat_feed_url.clone() {
        feed::spawn_feed_sync(
            feed::FeedConfig {
                name: "hub-threat-feed".to_string(),
                url: feed_url,
                interval_s: args.threat_feed_interval_s,
                action: args.threat_feed_action,
                ttl_s: args.threat_feed_ttl_s,
            },
            Arc::clone(&store),
        );
    }

    let state = Arc::new(AppState {
        store,
        registry: Arc::clone(&registry),
        auth: HubAuth::new(token),
        rate_limiter,
        node_timeout_ns: args.node_timeout_s * 1_000_000_000,
    });

    let addr: SocketAddr = args.bind.parse().context("parse bind address")?;
    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();

    match (args.tls_cert, args.tls_key) {
        (Some(cert), Some(key)) => {
            let tls_config = tls::load_rustls_config(&cert, &key, args.tls_client_ca.as_deref())
                .context("load TLS config")?;
            tracing::info!(%addr, "starting HTTPS hub");
            axum_server::bind_rustls(addr, tls_config)
                .serve(app)
                .await
                .context("serve HTTPS")?;
        }
        (None, None) => {
            tracing::warn!(%addr, "starting HTTP hub without TLS");
            axum_server::bind(addr)
                .serve(app)
                .await
                .context("serve HTTP")?;
        }
        _ => {
            bail!("--tls-cert and --tls-key must be provided together");
        }
    }

    Ok(())
}

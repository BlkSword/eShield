use axum::{
    extract::State,
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Request, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::{self, AuthState};
use crate::audit::{AuditAction, Auditor};
use crate::control::{ControlState, RuntimeConfigPatch};
use crate::health;
use crate::ip::format_ip_key;
use crate::state::Stats;

pub struct WebState {
    pub stats: Arc<Stats>,
    pub control: Arc<ControlState>,
    pub auditor: Auditor,
    pub auth: AuthState,
}

pub async fn run(
    stats: Arc<Stats>,
    control: Arc<ControlState>,
    auditor: Auditor,
    auth: AuthState,
    bind: String,
) -> anyhow::Result<()> {
    let state = Arc::new(WebState {
        stats,
        control,
        auditor,
        auth,
    });

    let public = Router::new()
        .route("/healthz", get(health::healthz_handler))
        .route("/ready", get(health::ready_handler));

    let protected = Router::new()
        .route("/", get(index_handler))
        .route("/api/stats", get(stats_handler))
        .route(
            "/api/config",
            get(config_handler).patch(patch_config_handler),
        )
        .route("/api/config/reload", post(reload_config_handler))
        .route(
            "/api/blacklist",
            post(block_ip_handler).delete(unblock_ip_handler),
        )
        .route(
            "/api/whitelist",
            post(allow_cidr_handler).delete(disallow_cidr_handler),
        )
        .route("/api/audit", get(audit_handler))
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware)));

    let app = public
        .merge(protected)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("web dashboard listening on http://{}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn auth_middleware(
    State(state): State<Arc<WebState>>,
    request: Request,
    next: Next,
) -> Response {
    auth::auth_middleware(State(state.auth.clone()), request, next).await
}

#[derive(Serialize)]
struct StatsResponse {
    total_dropped: u64,
    blacklist_blocked: u64,
    rate_limited: u64,
    syn_flood_blocked: u64,
    l7_blocked: u64,
    adaptive_blocked: u64,
    udp_flood_blocked: u64,
    icmp_flood_blocked: u64,
    top_attackers: Vec<Attacker>,
}

#[derive(Serialize)]
struct Attacker {
    ip: String,
    count: u64,
}

#[derive(Deserialize)]
struct BlockIpReq {
    ip: String,
    #[serde(default)]
    duration_s: u64,
}

#[derive(Deserialize)]
struct UnblockIpReq {
    ip: String,
}

#[derive(Deserialize)]
struct AllowCidrReq {
    cidr: String,
}

#[derive(Deserialize)]
struct DisallowCidrReq {
    cidr: String,
}

async fn stats_handler(State(state): State<Arc<WebState>>) -> Json<StatsResponse> {
    Json(stats_snapshot(&state.stats).await)
}

async fn config_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await.clone();
    Json(serde_json::to_value(rt).unwrap_or_default())
}

async fn patch_config_handler(
    State(state): State<Arc<WebState>>,
    Json(patch): Json<RuntimeConfigPatch>,
) -> Result<&'static str, (StatusCode, String)> {
    state
        .control
        .patch_runtime(patch)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("配置已更新")
}

async fn reload_config_handler(
    State(state): State<Arc<WebState>>,
) -> Result<&'static str, (StatusCode, String)> {
    state
        .control
        .reload_config_file()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("配置已从文件重新加载")
}

async fn block_ip_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<BlockIpReq>,
) -> Result<&'static str, (StatusCode, String)> {
    state
        .control
        .block_ip(&req.ip, req.duration_s)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已封禁")
}

async fn unblock_ip_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<UnblockIpReq>,
) -> Result<&'static str, (StatusCode, String)> {
    state
        .control
        .unblock_ip(&req.ip)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已解封")
}

async fn allow_cidr_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<AllowCidrReq>,
) -> Result<&'static str, (StatusCode, String)> {
    state
        .control
        .allow_cidr(&req.cidr)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已加入白名单")
}

async fn disallow_cidr_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<DisallowCidrReq>,
) -> Result<&'static str, (StatusCode, String)> {
    state
        .control
        .disallow_cidr(&req.cidr)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已移除白名单")
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
}

fn default_audit_limit() -> usize {
    100
}

async fn audit_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let entries = state
        .auditor
        .list(q.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({ "entries": entries })))
}

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

async fn index_handler(State(state): State<Arc<WebState>>) -> Html<String> {
    let config_json = serde_json::to_string(&*state.control.runtime.read().await)
        .unwrap_or_else(|_| "{}".to_string());
    Html(DASHBOARD_HTML.replacen("__CONFIG_JSON__", &config_json, 1))
}

async fn stats_snapshot(stats: &Arc<Stats>) -> StatsResponse {
    let mut top_attackers: Vec<Attacker> = stats
        .top_attackers
        .iter()
        .map(|entry| Attacker {
            ip: format_ip_key(entry.key()),
            count: entry.value().load(std::sync::atomic::Ordering::Relaxed),
        })
        .collect();
    top_attackers.sort_by_key(|a| std::cmp::Reverse(a.count));
    top_attackers.truncate(20);

    StatsResponse {
        total_dropped: stats
            .total_dropped
            .load(std::sync::atomic::Ordering::Relaxed),
        blacklist_blocked: stats
            .blacklist_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        rate_limited: stats
            .rate_limited
            .load(std::sync::atomic::Ordering::Relaxed),
        syn_flood_blocked: stats
            .syn_flood_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        l7_blocked: stats.l7_blocked.load(std::sync::atomic::Ordering::Relaxed),
        adaptive_blocked: stats
            .adaptive_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        udp_flood_blocked: stats
            .udp_flood_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        icmp_flood_blocked: stats
            .icmp_flood_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        top_attackers,
    }
}

async fn metrics_handler(State(state): State<Arc<WebState>>) -> Response {
    let stats = stats_snapshot(&state.stats).await;
    let mut body = format!(
        "# HELP eshield_dropped_total Total dropped packets\n\
         # TYPE eshield_dropped_total counter\n\
         eshield_dropped_total {}\n\n\
         # HELP eshield_blacklist_blocked_total Blacklist blocked packets\n\
         # TYPE eshield_blacklist_blocked_total counter\n\
         eshield_blacklist_blocked_total {}\n\n\
         # HELP eshield_rate_limited_total Rate limited packets\n\
         # TYPE eshield_rate_limited_total counter\n\
         eshield_rate_limited_total {}\n\n\
         # HELP eshield_syn_flood_blocked_total SYN flood blocked packets\n\
         # TYPE eshield_syn_flood_blocked_total counter\n\
         eshield_syn_flood_blocked_total {}\n\n\
         # HELP eshield_l7_blocked_total L7 scan blocked packets\n\
         # TYPE eshield_l7_blocked_total counter\n\
         eshield_l7_blocked_total {}\n\n\
         # HELP eshield_adaptive_blocked_total Adaptive threshold blocked packets\n\
         # TYPE eshield_adaptive_blocked_total counter\n\
         eshield_adaptive_blocked_total {}\n\n\
         # HELP eshield_udp_flood_blocked_total UDP flood blocked packets\n\
         # TYPE eshield_udp_flood_blocked_total counter\n\
         eshield_udp_flood_blocked_total {}\n\n\
         # HELP eshield_icmp_flood_blocked_total ICMP flood blocked packets\n\
         # TYPE eshield_icmp_flood_blocked_total counter\n\
         eshield_icmp_flood_blocked_total {}\n",
        stats.total_dropped,
        stats.blacklist_blocked,
        stats.rate_limited,
        stats.syn_flood_blocked,
        stats.l7_blocked,
        stats.adaptive_blocked,
        stats.udp_flood_blocked,
        stats.icmp_flood_blocked,
    );

    for attacker in &stats.top_attackers {
        body.push_str(&format!(
            "\n# HELP eshield_source_dropped_total Dropped packets per source IP\n\
             # TYPE eshield_source_dropped_total counter\n\
             eshield_source_dropped_total{{ip=\"{}\"}} {}\n",
            attacker.ip, attacker.count
        ));
    }

    ([("content-type", "text/plain; charset=utf-8")], body).into_response()
}

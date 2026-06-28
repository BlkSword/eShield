use axum::{
    extract::{ConnectInfo, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::auth::{self, AuthState};
use crate::audit::Auditor;
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
        .route("/ready", get(health::ready_handler))
        .route("/challenge", get(challenge_handler))
        .route("/api/challenge/pass", post(challenge_pass_handler))
        .with_state(state.clone());

    let protected = Router::new()
        .route("/", get(index_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/metrics/series", get(metrics_series_handler))
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
        .route("/api/waf/rules", get(list_waf_rules_handler).post(set_waf_rules_handler))
        .route("/api/waf/rules/reorder", post(reorder_waf_rules_handler))
        .route("/api/port-acl", get(list_port_acl_handler).post(set_port_acl_handler))
        .route("/api/l7-patterns", get(list_l7_patterns_handler).post(set_l7_patterns_handler))
        .route("/api/geoip/reload", post(reload_geoip_handler))
        .route("/api/threat-intel/sync", post(sync_threat_intel_handler))
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let app = public.merge(protected);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("web dashboard listening on http://{}", bind);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
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
    total_packets: u64,
    total_passed: u64,
    total_dropped: u64,
    current_pps: u64,
    current_dps: u64,
    blacklist_blocked: u64,
    rate_limited: u64,
    syn_flood_blocked: u64,
    l7_blocked: u64,
    adaptive_blocked: u64,
    udp_flood_blocked: u64,
    icmp_flood_blocked: u64,
    waf_blocked: u64,
    geoip_blocked: u64,
    challenge_issued: u64,
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

#[derive(Deserialize)]
struct ChallengePassReq {
    ip: String,
    nonce: String,
    answer: u64,
}

#[derive(Deserialize)]
struct SetWafRulesReq {
    rules: Vec<crate::config::WafRuleItem>,
}

#[derive(Deserialize)]
struct ReorderWafRulesReq {
    names: Vec<String>,
}

#[derive(Deserialize)]
struct SetPortAclReq {
    items: Vec<crate::config::PortAclItem>,
}

#[derive(Deserialize)]
struct SetL7PatternsReq {
    patterns: Vec<crate::config::L7PatternConfig>,
}

/// Challenge 签名密钥，用于防止 nonce 伪造（硬编码，生产环境应使用配置或随机启动密钥）。
const CHALLENGE_SECRET: u64 = 0x5f37_9a21_b4cd_8e01;

async fn challenge_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    let a = rand::random::<u64>() % 10_000;
    let b = rand::random::<u64>() % 10_000;
    let sig = a ^ b ^ CHALLENGE_SECRET;
    let nonce = format!("{}:{}:{}", a, b, sig);
    let html = include_str!("challenge.html")
        .replace("{nonce}", &nonce)
        .replace("{ip}", &addr.ip().to_string());
    Html(html)
}

async fn challenge_pass_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<ChallengePassReq>,
) -> Result<&'static str, (StatusCode, String)> {
    let parts: Vec<&str> = req.nonce.split(':').collect();
    if parts.len() != 3 {
        return Err((StatusCode::BAD_REQUEST, "invalid nonce format".to_string()));
    }
    let a = parts[0]
        .parse::<u64>()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce: {}", e)))?;
    let b = parts[1]
        .parse::<u64>()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce: {}", e)))?;
    let sig = parts[2]
        .parse::<u64>()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce: {}", e)))?;
    if sig != (a ^ b ^ CHALLENGE_SECRET) {
        return Err((StatusCode::BAD_REQUEST, "invalid nonce signature".to_string()));
    }
    if req.answer != a.saturating_add(b) {
        return Err((StatusCode::BAD_REQUEST, "incorrect answer".to_string()));
    }

    let ttl_s = state.control.runtime.read().await.challenge_ttl_s;
    state
        .control
        .challenge_allow(&req.ip, ttl_s)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("验证通过，已加入临时白名单")
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

#[derive(Deserialize)]
struct SeriesQuery {
    #[serde(default = "default_series_duration")]
    duration_s: u64,
}

fn default_series_duration() -> u64 {
    3600
}

async fn metrics_series_handler(
    State(state): State<Arc<WebState>>,
    Query(q): Query<SeriesQuery>,
) -> Json<serde_json::Value> {
    let series = state
        .stats
        .timeseries
        .read()
        .await
        .snapshot(q.duration_s);
    Json(serde_json::json!({ "series": series }))
}

async fn list_waf_rules_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await;
    Json(serde_json::json!({ "rules": rt.waf_rules }))
}

async fn list_port_acl_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await;
    Json(serde_json::json!({ "items": rt.port_acl }))
}

async fn set_port_acl_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SetPortAclReq>,
) -> Result<&'static str, (StatusCode, String)> {
    if req.items.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "too many port_acl entries (max 128)".to_string()));
    }
    state
        .control
        .set_port_acl(req.items)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("端口 ACL 已更新")
}

async fn list_l7_patterns_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await;
    Json(serde_json::json!({ "patterns": rt.l7_scan.patterns }))
}

async fn set_l7_patterns_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SetL7PatternsReq>,
) -> Result<&'static str, (StatusCode, String)> {
    if req.patterns.len() > 16 {
        return Err((StatusCode::BAD_REQUEST, "too many L7 patterns (max 16)".to_string()));
    }
    state
        .control
        .set_l7_patterns(req.patterns)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("L7 指纹已更新")
}

async fn reload_geoip_handler(
    State(state): State<Arc<WebState>>,
) -> Result<&'static str, (StatusCode, String)> {
    state
        .control
        .reload_geoip()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("GeoIP 已重新加载")
}

async fn sync_threat_intel_handler(State(state): State<Arc<WebState>>) -> &'static str {
    let feeds = state.control.runtime.read().await.threat_intel_feeds.clone();
    for feed in feeds {
        let control = state.control.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::threat_intel::sync_feed_now(control, feed).await {
                tracing::warn!("manual threat intel sync failed: {}", e);
            }
        });
    }
    "威胁情报同步已触发"
}

async fn set_waf_rules_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SetWafRulesReq>,
) -> Result<&'static str, (StatusCode, String)> {
    if req.rules.len() > eshield_common::WAF_RULES_MAX {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("too many WAF rules (max {})", eshield_common::WAF_RULES_MAX),
        ));
    }
    state
        .control
        .set_waf_rules(req.rules)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("WAF 规则已更新")
}

async fn reorder_waf_rules_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<ReorderWafRulesReq>,
) -> Result<&'static str, (StatusCode, String)> {
    let mut rules = state.control.runtime.read().await.waf_rules.clone();
    let mut new_order: Vec<crate::config::WafRuleItem> = Vec::with_capacity(req.names.len());
    for name in &req.names {
        if let Some(pos) = rules.iter().position(|r| &r.name == name) {
            new_order.push(rules.remove(pos));
        } else {
            return Err((StatusCode::BAD_REQUEST, format!("rule not found: {}", name)));
        }
    }
    new_order.extend(rules);
    state
        .control
        .set_waf_rules(new_order)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("WAF 规则顺序已更新")
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
        total_packets: stats.total_packets.load(Ordering::Relaxed),
        total_passed: stats.total_passed.load(Ordering::Relaxed),
        total_dropped: stats.total_dropped.load(Ordering::Relaxed),
        current_pps: stats.current_pps.load(Ordering::Relaxed),
        current_dps: stats.current_dps.load(Ordering::Relaxed),
        blacklist_blocked: stats.blacklist_blocked.load(Ordering::Relaxed),
        rate_limited: stats.rate_limited.load(Ordering::Relaxed),
        syn_flood_blocked: stats.syn_flood_blocked.load(Ordering::Relaxed),
        l7_blocked: stats.l7_blocked.load(Ordering::Relaxed),
        adaptive_blocked: stats.adaptive_blocked.load(Ordering::Relaxed),
        udp_flood_blocked: stats.udp_flood_blocked.load(Ordering::Relaxed),
        icmp_flood_blocked: stats.icmp_flood_blocked.load(Ordering::Relaxed),
        waf_blocked: stats.waf_blocked.load(Ordering::Relaxed),
        geoip_blocked: stats.geoip_blocked.load(Ordering::Relaxed),
        challenge_issued: stats.challenge_issued.load(Ordering::Relaxed),
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
         eshield_icmp_flood_blocked_total {}\n\n\
         # HELP eshield_waf_blocked_total WAF blocked packets\n\
         # TYPE eshield_waf_blocked_total counter\n\
         eshield_waf_blocked_total {}\n\n\
         # HELP eshield_geoip_blocked_total GeoIP blocked packets\n\
         # TYPE eshield_geoip_blocked_total counter\n\
         eshield_geoip_blocked_total {}\n\n\
         # HELP eshield_challenge_issued_total Challenge issued\n\
         # TYPE eshield_challenge_issued_total counter\n\
         eshield_challenge_issued_total {}\n",
        stats.total_dropped,
        stats.blacklist_blocked,
        stats.rate_limited,
        stats.syn_flood_blocked,
        stats.l7_blocked,
        stats.adaptive_blocked,
        stats.udp_flood_blocked,
        stats.icmp_flood_blocked,
        stats.waf_blocked,
        stats.geoip_blocked,
        stats.challenge_issued,
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

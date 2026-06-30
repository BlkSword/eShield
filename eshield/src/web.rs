use axum::{
    extract::{ConnectInfo, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{sse::Event, Html, IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use futures::{Stream, StreamExt};
use std::convert::Infallible;
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use chrono::Utc;

use crate::auth::{self, AuthState};
use crate::audit::{AuditAction, Auditor};
use crate::control::{ControlState, RuntimeConfigPatch};
use crate::health;
use crate::ip::format_ip_key;
use crate::login_limiter::LoginLimiter;
use crate::state::Stats;

fn map_data(map: &aya::maps::Map) -> Option<&aya::maps::MapData> {
    use aya::maps::Map;
    match map {
        Map::Array(m) => Some(m),
        Map::HashMap(m) => Some(m),
        Map::LpmTrie(m) => Some(m),
        Map::PerfEventArray(m) => Some(m),
        Map::ProgramArray(m) => Some(m),
        Map::SockHash(m) => Some(m),
        Map::SockMap(m) => Some(m),
        Map::StackTraceMap(m) => Some(m),
        Map::BloomFilter(m) => Some(m),
        Map::LruHashMap(m) => Some(m),
        Map::PerCpuArray(m) => Some(m),
        Map::PerCpuHashMap(m) => Some(m),
        Map::Queue(m) => Some(m),
        Map::RingBuf(m) => Some(m),
        Map::Stack(m) => Some(m),
        _ => None,
    }
}

pub struct WebState {
    pub stats: Arc<Stats>,
    pub control: Arc<ControlState>,
    pub auditor: Auditor,
    pub auth: AuthState,
    pub login_limiter: Arc<LoginLimiter>,
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
        login_limiter: Arc::new(LoginLimiter::new()),
    });

    let public = Router::new()
        .route("/healthz", get(health::healthz_handler))
        .route("/ready", get(health::ready_handler))
        .route("/login", get(login_handler))
        .route("/challenge", get(challenge_handler))
        .route("/blocked", get(blocked_handler))
        .route("/api/challenge/pass", post(challenge_pass_handler))
        .route("/api/auth/login", post(login_api_handler))
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
        .route("/api/auth/check", get(auth_check_handler))
        .route("/api/auth/reset-token", post(reset_token_handler))
        .route("/api/protection-modules", get(protection_modules_handler))
        .route(
            "/api/blacklist",
            post(block_ip_handler).delete(unblock_ip_handler),
        )
        .route(
            "/api/whitelist",
            post(allow_cidr_handler).delete(disallow_cidr_handler),
        )
        .route("/api/audit", get(audit_handler))
        .route("/api/audit/stream", get(audit_stream_handler))
        .route("/api/metrics/attacker-series", get(attacker_series_handler))
        .route("/api/waf/rules", get(list_waf_rules_handler).post(set_waf_rules_handler))
        .route("/api/waf/rules/reorder", post(reorder_waf_rules_handler))
        .route("/api/port-acl", get(list_port_acl_handler).post(set_port_acl_handler))
        .route(
            "/api/protection-projects",
            get(list_protection_projects_handler).post(set_protection_projects_handler),
        )
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
struct LoginReq {
    token: String,
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
struct SetProtectionProjectsReq {
    projects: Vec<crate::config::ProtectionProject>,
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

const BLOCKED_HTML: &str = include_str!("blocked.html");

async fn blocked_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    let html = BLOCKED_HTML
        .replace("{ip}", &addr.ip().to_string())
        .replace("{timestamp}", &Utc::now().to_rfc3339())
        .replace("{request_id}", &format!("{:08x}", rand::random::<u32>()));
    Html(html)
}

async fn login_handler() -> Html<String> {
    Html(include_str!("login.html").to_string())
}

async fn login_api_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<WebState>>,
    Json(req): Json<LoginReq>,
) -> Response {
    let ip = addr.ip();
    if let Err(msg) = state.login_limiter.check(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
    }

    if state.auth.verify(&req.token).await {
        state.login_limiter.record_success(ip);
        state
            .auditor
            .log(
                "console",
                AuditAction::Login,
                serde_json::json!({"ip": ip.to_string(), "result": "success"}),
                Some(ip.to_string()),
            )
            .await;
        (StatusCode::OK, "OK").into_response()
    } else {
        state.login_limiter.record_failure(ip);
        state
            .auditor
            .log(
                "console",
                AuditAction::Login,
                serde_json::json!({"ip": ip.to_string(), "result": "failed"}),
                Some(ip.to_string()),
            )
            .await;
        (StatusCode::UNAUTHORIZED, "Invalid token").into_response()
    }
}

async fn auth_check_handler() -> &'static str {
    "OK"
}

async fn reset_token_handler(State(state): State<Arc<WebState>>) -> Response {
    let new_token = state.auth.reset_token().await;
    state
        .auditor
        .log(
            "console",
            AuditAction::ResetToken,
            serde_json::json!({"token_prefix": &new_token[..8]}),
            None,
        )
        .await;
    Json(serde_json::json!({"token": new_token})).into_response()
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

async fn protection_modules_handler(
    State(state): State<Arc<WebState>>,
) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await.clone();
    let modules = vec![
        serde_json::json!({
            "id": "syn_flood",
            "name": "SYN Flood 防护",
            "category": "DDoS",
            "description": "基于 SYN 代理/ cookie 抵御 SYN Flood 攻击。",
            "enabled": rt.syn_proxy_enabled,
            "stats_key": "syn_flood_blocked",
            "editable_fields": [field_switch("enabled", "启用防护", rt.syn_proxy_enabled)]
        }),
        serde_json::json!({
            "id": "udp_flood",
            "name": "UDP Flood 防护",
            "category": "DDoS",
            "description": "检测并丢弃异常 UDP 泛洪流量。",
            "enabled": rt.udp_flood_enabled,
            "stats_key": "udp_flood_blocked",
            "editable_fields": [field_switch("enabled", "启用防护", rt.udp_flood_enabled)]
        }),
        serde_json::json!({
            "id": "icmp_flood",
            "name": "ICMP Flood 防护",
            "category": "DDoS",
            "description": "检测并丢弃异常 ICMP/ICMPv6 泛洪流量。",
            "enabled": rt.icmp_flood_enabled,
            "stats_key": "icmp_flood_blocked",
            "editable_fields": [field_switch("enabled", "启用防护", rt.icmp_flood_enabled)]
        }),
        serde_json::json!({
            "id": "rate_limit",
            "name": "速率限制 / CC 防护",
            "category": "访问控制",
            "description": "基于令牌桶对每个源 IP 进行速率限制。",
            "enabled": rt.rate_limit.enabled,
            "stats_key": "rate_limited",
            "editable_fields": [
                field_switch("enabled", "启用限速", rt.rate_limit.enabled),
                field_number("threshold", "阈值（包/窗口）", rt.rate_limit.threshold),
                field_number("tick_ms", "窗口 Tick (ms)", rt.rate_limit.tick_ms),
                field_number("decay_num", "衰减分子", rt.rate_limit.decay_num),
                field_number("decay_den", "衰减分母", rt.rate_limit.decay_den),
                field_number("block_duration_s", "封禁时长 (s)", rt.rate_limit.block_duration_s)
            ]
        }),
        serde_json::json!({
            "id": "adaptive",
            "name": "自适应黑名单",
            "category": "访问控制",
            "description": "对短时间窗口内多次触发规则的源 IP 自动追加黑名单。",
            "enabled": rt.adaptive.enabled,
            "stats_key": "adaptive_blocked",
            "editable_fields": [
                field_switch("enabled", "启用自适应", rt.adaptive.enabled),
                field_number("threshold", "触发阈值（次）", rt.adaptive.threshold),
                field_number("window_s", "统计窗口 (s)", rt.adaptive.window_s),
                field_number("block_duration_s", "封禁时长 (s)", rt.adaptive.block_duration_s)
            ]
        }),
        serde_json::json!({
            "id": "waf",
            "name": "WAF 规则引擎",
            "category": "应用层",
            "description": "基于 Method/Path/Host/UA 的 HTTP 层规则匹配。",
            "enabled": rt.waf_enabled,
            "stats_key": "waf_blocked",
            "editable_fields": [field_switch("enabled", "启用 WAF", rt.waf_enabled)]
        }),
        serde_json::json!({
            "id": "l7_scan",
            "name": "L7 指纹扫描",
            "category": "应用层",
            "description": "匹配应用层指纹特征，识别扫描/探测行为。",
            "enabled": rt.l7_scan_enabled,
            "stats_key": "l7_blocked",
            "editable_fields": [field_switch("enabled", "启用 L7 扫描", rt.l7_scan_enabled)]
        }),
        serde_json::json!({
            "id": "geoip",
            "name": "GeoIP 地区封禁",
            "category": "访问控制",
            "description": "根据国家/地区或 ASN 放行或封禁流量。",
            "enabled": rt.geoip_enabled,
            "stats_key": "geoip_blocked",
            "editable_fields": [field_switch("enabled", "启用 GeoIP", rt.geoip_enabled)]
        }),
        serde_json::json!({
            "id": "challenge",
            "name": "挑战验证（人机验证）",
            "category": "应用层",
            "description": "对可疑客户端下发 JS/302 挑战，通过后加入临时白名单。",
            "enabled": rt.challenge_enabled,
            "stats_key": "challenge_issued",
            "editable_fields": [
                field_switch("enabled", "启用挑战", rt.challenge_enabled),
                field_select("mode", "验证模式", vec!["js", "302"], &rt.challenge_mode),
                field_number("ttl_s", "放行有效期 (s)", rt.challenge_ttl_s)
            ]
        }),
        serde_json::json!({
            "id": "tcp_reset",
            "name": "TCP RST 回包",
            "category": "网络层",
            "description": "对丢弃的 TCP 连接回复 RST，加速客户端失败重连。",
            "enabled": rt.tcp_reset_on_drop,
            "stats_key": None::<String>,
            "editable_fields": [field_switch("enabled", "启用 RST 回包", rt.tcp_reset_on_drop)]
        }),
        serde_json::json!({
            "id": "port_acl",
            "name": "端口 ACL",
            "category": "访问控制",
            "description": "基于协议和目的端口的显式 allow/drop 规则。",
            "enabled": !rt.port_acl.is_empty(),
            "stats_key": None::<String>,
            "editable_fields": [
                field_readonly("rules_count", "已配置规则数", serde_json::json!(rt.port_acl.len()))
            ]
        }),
    ];
    Json(serde_json::json!({ "modules": modules }))
}

fn field_switch(id: &str, label: &str, value: bool) -> serde_json::Value {
    serde_json::json!({"id": id, "type": "switch", "label": label, "value": value})
}

fn field_number(id: &str, label: &str, value: u64) -> serde_json::Value {
    serde_json::json!({"id": id, "type": "number", "label": label, "value": value})
}

fn field_select(id: &str, label: &str, options: Vec<&str>, value: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "type": "select", "label": label, "options": options, "value": value})
}

fn field_readonly(id: &str, label: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"id": id, "type": "readonly", "label": label, "value": value})
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
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
}

fn default_audit_limit() -> usize {
    100
}

#[derive(Deserialize)]
struct SeriesQuery {
    #[serde(default = "default_series_duration")]
    duration_s: u64,
}

#[derive(Deserialize)]
struct AttackerSeriesQuery {
    ip: String,
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

async fn list_protection_projects_handler(
    State(state): State<Arc<WebState>>,
) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await;
    Json(serde_json::json!({ "projects": rt.protection_projects }))
}

async fn set_protection_projects_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SetProtectionProjectsReq>,
) -> Result<&'static str, (StatusCode, String)> {
    if req.projects.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "too many protection projects (max 256)".to_string(),
        ));
    }
    state
        .control
        .set_protection_projects(req.projects)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("防护项目已更新")
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
        .list(10_000)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let ip_filter = q.ip.as_deref().map(|s| s.to_lowercase());
    let action_filter = q.action.as_deref().map(|s| s.to_lowercase());

    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            if let Some(ip) = &ip_filter {
                let hay = format!(
                    "{} {} {}",
                    e.source_ip.as_deref().unwrap_or(""),
                    e.actor,
                    serde_json::to_string(&e.detail).unwrap_or_default()
                )
                .to_lowercase();
                if !hay.contains(ip) {
                    return false;
                }
            }
            if let Some(action) = &action_filter {
                let a = serde_json::to_value(&e.action)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_lowercase()))
                    .unwrap_or_default();
                if a != *action {
                    return false;
                }
            }
            if let Some(from) = q.from.as_deref() {
                if e.timestamp.as_str() < from {
                    return false;
                }
            }
            if let Some(to) = q.to.as_deref() {
                if e.timestamp.as_str() > to {
                    return false;
                }
            }
            true
        })
        .rev()
        .take(q.limit)
        .collect();

    Ok(Json(serde_json::json!({ "entries": filtered })))
}

async fn audit_stream_handler(
    State(state): State<Arc<WebState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.auditor.subscribe();
    let stream = BroadcastStream::new(rx).map(|result| {
        match result {
            Ok(entry) => {
                let data = serde_json::to_string(&entry).unwrap_or_default();
                Ok(Event::default().event("audit").data(data))
            }
            Err(_) => Ok(Event::default().event("ping").data("")),
        }
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

async fn attacker_series_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<AttackerSeriesQuery>,
) -> Json<serde_json::Value> {
    let series = state
        .stats
        .timeseries
        .read()
        .await
        .snapshot(q.duration_s);
    let points: Vec<serde_json::Value> = series
        .iter()
        .map(|p| {
            serde_json::json!({
                "timestamp": p.timestamp,
                "count": p.top_attackers.get(&q.ip).copied().unwrap_or(0),
            })
        })
        .collect();
    Json(serde_json::json!({ "ip": q.ip, "series": points }))
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
    let interface = state.control.runtime.read().await.interface.clone();

    let tcp = state.stats.tcp_dropped.load(Ordering::Relaxed);
    let udp = state.stats.udp_dropped.load(Ordering::Relaxed);
    let icmp = state.stats.icmp_dropped.load(Ordering::Relaxed);
    let other = state.stats.other_dropped.load(Ordering::Relaxed);

    let mut body = format!(
        "# HELP eshield_dropped_total Total dropped packets\n\
         # TYPE eshield_dropped_total counter\n\
         eshield_dropped_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_passed_total Total passed packets\n\
         # TYPE eshield_passed_total counter\n\
         eshield_passed_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_blacklist_blocked_total Blacklist blocked packets\n\
         # TYPE eshield_blacklist_blocked_total counter\n\
         eshield_blacklist_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_rate_limited_total Rate limited packets\n\
         # TYPE eshield_rate_limited_total counter\n\
         eshield_rate_limited_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_syn_flood_blocked_total SYN flood blocked packets\n\
         # TYPE eshield_syn_flood_blocked_total counter\n\
         eshield_syn_flood_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_l7_blocked_total L7 scan blocked packets\n\
         # TYPE eshield_l7_blocked_total counter\n\
         eshield_l7_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_adaptive_blocked_total Adaptive threshold blocked packets\n\
         # TYPE eshield_adaptive_blocked_total counter\n\
         eshield_adaptive_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_udp_flood_blocked_total UDP flood blocked packets\n\
         # TYPE eshield_udp_flood_blocked_total counter\n\
         eshield_udp_flood_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_icmp_flood_blocked_total ICMP flood blocked packets\n\
         # TYPE eshield_icmp_flood_blocked_total counter\n\
         eshield_icmp_flood_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_waf_blocked_total WAF blocked packets\n\
         # TYPE eshield_waf_blocked_total counter\n\
         eshield_waf_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_geoip_blocked_total GeoIP blocked packets\n\
         # TYPE eshield_geoip_blocked_total counter\n\
         eshield_geoip_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_challenge_issued_total Challenge issued\n\
         # TYPE eshield_challenge_issued_total counter\n\
         eshield_challenge_issued_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_dropped_by_protocol_total Dropped packets by IP protocol\n\
         # TYPE eshield_dropped_by_protocol_total counter\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"tcp\"}} {}\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"udp\"}} {}\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"icmp\"}} {}\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"other\"}} {}\n",
        interface, stats.total_dropped,
        interface, stats.total_passed,
        interface, stats.blacklist_blocked,
        interface, stats.rate_limited,
        interface, stats.syn_flood_blocked,
        interface, stats.l7_blocked,
        interface, stats.adaptive_blocked,
        interface, stats.udp_flood_blocked,
        interface, stats.icmp_flood_blocked,
        interface, stats.waf_blocked,
        interface, stats.geoip_blocked,
        interface, stats.challenge_issued,
        interface, tcp, interface, udp, interface, icmp, interface, other,
    );

    for attacker in &stats.top_attackers {
        body.push_str(&format!(
            "\n# HELP eshield_source_dropped_total Dropped packets per source IP\n\
             # TYPE eshield_source_dropped_total counter\n\
             eshield_source_dropped_total{{interface=\"{}\",ip=\"{}\"}} {}\n",
            interface, attacker.ip, attacker.count
        ));
    }

    let mut ports: Vec<(u16, u64)> = state
        .stats
        .port_dropped
        .iter()
        .map(|e| (*e.key(), e.value().load(Ordering::Relaxed)))
        .collect();
    ports.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    ports.truncate(10);
    if !ports.is_empty() {
        body.push_str("\n# HELP eshield_dropped_by_port_total Dropped packets by destination port\n# TYPE eshield_dropped_by_port_total counter\n");
        for (port, count) in ports {
            body.push_str(&format!(
                "eshield_dropped_by_port_total{{interface=\"{}\",port=\"{}\"}} {}\n",
                interface, port, count
            ));
        }
    }

    // Event consumer processing duration histogram (microseconds)
    let buckets = ["1000", "5000", "10000", "50000", "100000", "+Inf"];
    body.push_str("\n# HELP eshield_event_consumer_duration_us Event consumer batch processing duration histogram\n# TYPE eshield_event_consumer_duration_us histogram\n");
    let mut cumulative = 0u64;
    for (i, le) in buckets.iter().enumerate() {
        let v = state.stats.process_hist[i].load(Ordering::Relaxed);
        cumulative += v;
        body.push_str(&format!(
            "eshield_event_consumer_duration_us_bucket{{interface=\"{}\",le=\"{}\"}} {}\n",
            interface, le, cumulative
        ));
    }
    body.push_str(&format!(
        "eshield_event_consumer_duration_us_sum{{interface=\"{}\"}} {}\neshield_event_consumer_duration_us_count{{interface=\"{}\"}} {}\n",
        interface, 0, interface, cumulative
    ));

    // eBPF map usage metrics
    {
        let mut guard = state.control.ebpf.lock().await;
        body.push_str("\n# HELP eshield_map_max_entries eBPF map max entries\n# TYPE eshield_map_max_entries gauge\n");
        for (name, map) in guard.maps() {
            if let Some(data) = map_data(map) {
                if let Ok(info) = data.info() {
                    let map_type_str = info
                        .map_type()
                        .map(|t| format!("{:?}", t))
                        .unwrap_or_default();
                    body.push_str(&format!(
                        "eshield_map_max_entries{{interface=\"{}\",name=\"{}\",map_type=\"{}\"}} {}\n",
                        interface,
                        name,
                        map_type_str,
                        info.max_entries()
                    ));
                }
            }
        }

        body.push_str("\n# HELP eshield_map_entries eBPF map current entries\n# TYPE eshield_map_entries gauge\n");
        use aya::maps::HashMap as LruHashMap;
        use eshield_common::{BlockEntry, IpKey, RateCounter};

        if let Some(map) = guard.map_mut("BLACKLIST") {
            let m: Result<LruHashMap<_, IpKey, BlockEntry>, _> = map.try_into();
            if let Ok(m) = m {
                body.push_str(&format!(
                    "eshield_map_entries{{interface=\"{}\",name=\"BLACKLIST\"}} {}\n",
                    interface,
                    m.iter().count()
                ));
            }
        }
        if let Some(map) = guard.map_mut("RATE_MAP") {
            let m: Result<LruHashMap<_, IpKey, RateCounter>, _> = map.try_into();
            if let Ok(m) = m {
                body.push_str(&format!(
                    "eshield_map_entries{{interface=\"{}\",name=\"RATE_MAP\"}} {}\n",
                    interface,
                    m.iter().count()
                ));
            }
        }
    }

    ([("content-type", "text/plain; charset=utf-8")], body).into_response()
}

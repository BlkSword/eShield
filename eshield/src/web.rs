use axum::{
    body::Body,
    extract::{ConnectInfo, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{sse::Event, Html, IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use aya::maps::HashMap as LruHashMap;
use chrono::Utc;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio_stream::wrappers::BroadcastStream;

use crate::audit::{AuditAction, Auditor};
use crate::auth::{self, AuthState};
use crate::control::{ControlState, RuntimeConfigPatch};
use crate::health;
use crate::ip::{format_ip_key, parse_ip};
use crate::login_limiter::LoginLimiter;
use crate::packet_log::{PacketLog, PacketLogQuery};
use crate::state::Stats;
use eshield_common::{BlockEntry, IpKey, TrustEntry};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Embedded ECharts library for offline dashboard use.
const ECHARTS_JS: &[u8] = include_bytes!("echarts.min.js");

/// 统一 API 错误响应体：`{ "error": "..." }`。
type ApiError = (StatusCode, Json<serde_json::Value>);

fn api_err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

fn api_err_response(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// HTTP request logging middleware: logs method, path, status, and duration.
async fn request_logger(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let start = Instant::now();
    let response = next.run(request).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    tracing::info!(
        event_type = "http",
        client_ip = %addr.ip(),
        method = %method,
        path = %path,
        status = status,
        elapsed_ms = elapsed_ms,
        "http request"
    );
    response
}

/// Body size limiting middleware: rejects requests with body > 1 MiB.
async fn body_size_limit(request: Request, next: Next) -> Response {
    const MAX_BODY: u64 = 1_048_576; // 1 MiB
    if let Some(len) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > MAX_BODY {
            return api_err_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }
    }
    next.run(request).await
}

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
    pub packet_log: Arc<PacketLog>,
}

pub async fn run(
    stats: Arc<Stats>,
    control: Arc<ControlState>,
    auditor: Auditor,
    auth: AuthState,
    bind: String,
    packet_log: Arc<PacketLog>,
) -> anyhow::Result<()> {
    let state = Arc::new(WebState {
        stats,
        control,
        auditor,
        auth,
        login_limiter: Arc::new(LoginLimiter::new()),
        packet_log,
    });

    let public = Router::new()
        .route("/healthz", get(health::healthz_handler))
        .route("/ready", get(health::ready_handler))
        .route("/login", get(login_handler))
        .route("/blocked", get(blocked_handler))
        .route("/static/echarts.min.js", get(echarts_handler))
        .route("/api/auth/login", post(login_api_handler))
        .layer(middleware::from_fn(request_logger))
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
        .route("/api/attack-events", get(attack_events_handler))
        .route("/api/packets", get(packets_handler))
        .route("/api/ip-detail", get(ip_detail_handler))
        .route("/api/ip-series", get(ip_series_handler))
        .route(
            "/api/port-acl",
            get(list_port_acl_handler).post(set_port_acl_handler),
        )
        .route(
            "/api/protection-projects",
            get(list_protection_projects_handler).post(set_protection_projects_handler),
        )
        .route(
            "/api/l7-patterns",
            get(list_l7_patterns_handler).post(set_l7_patterns_handler),
        )
        .route("/api/geoip/reload", post(reload_geoip_handler))
        .route("/api/threat-intel/sync", post(sync_threat_intel_handler))
        .route("/api/hub/status", get(hub_status_handler))
        .route("/api/hub/proxy/stats", get(hub_proxy_stats_handler))
        .route("/api/hub/proxy/nodes", get(hub_proxy_nodes_handler))
        .route("/api/hub/proxy/policies", get(hub_proxy_policies_handler))
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn(body_size_limit))
        .layer(middleware::from_fn(request_logger))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state.clone());

    let app = public.merge(protected);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("web dashboard listening on http://{}", bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn auth_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<WebState>>,
    request: Request,
    next: Next,
) -> Response {
    auth::auth_middleware(ConnectInfo(addr), State(state.auth.clone()), request, next).await
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
    geoip_blocked: u64,
    tcp_rst_sent: u64,
    tcp_rst_fail: u64,
    tcp_rst_attempt: u64,
    tcp_dropped: u64,
    udp_dropped: u64,
    icmp_dropped: u64,
    other_dropped: u64,
    top_attackers: Vec<Attacker>,
    top_ports: Vec<PortDrop>,
    /// Trust Score 信誉分布（v0.4.0）
    trust_trusted: u64,
    trust_neutral: u64,
    trust_suspicious: u64,
    trust_malicious: u64,
    /// 全局危险等级 0/1/2（v0.4.0）
    danger_level: u64,
}

#[derive(Serialize)]
struct Attacker {
    ip: String,
    count: u64,
}

#[derive(Serialize)]
struct PortDrop {
    port: u16,
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
struct LoginReq {
    token: String,
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

const BLOCKED_HTML: &str = include_str!("blocked.html");

async fn blocked_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    let html = BLOCKED_HTML
        .replace("{ip}", &addr.ip().to_string())
        .replace("{timestamp}", &Utc::now().to_rfc3339())
        .replace("{request_id}", &format!("{:08x}", rand::random::<u32>()));
    Html(html)
}

/// Serve embedded ECharts from binary (no CDN dependency).
async fn echarts_handler() -> Response {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        ECHARTS_JS,
    )
        .into_response()
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
        return api_err_response(StatusCode::TOO_MANY_REQUESTS, msg);
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
        let cookie = format!(
            "eshield-token={}; Path=/; HttpOnly; SameSite=Lax",
            req.token
        );
        Response::builder()
            .status(StatusCode::OK)
            .header("Set-Cookie", cookie)
            .body(Body::from("OK"))
            .unwrap()
            .into_response()
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
        api_err_response(StatusCode::UNAUTHORIZED, "Invalid token")
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

async fn stats_handler(State(state): State<Arc<WebState>>) -> Json<StatsResponse> {
    Json(stats_snapshot(&state.stats).await)
}

async fn config_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await.clone();
    Json(serde_json::to_value(rt).unwrap_or_default())
}

async fn protection_modules_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
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
            "id": "tcp_reset",
            "name": "TCP RST 回包",
            "category": "网络层",
            "description": "对丢弃的 TCP 连接回复 RST，加速客户端失败重连。",
            "enabled": rt.tcp_reset_on_drop,
            "stats_key": None::<String>,
            "editable_fields": [field_switch("enabled", "启用 RST 回包", rt.tcp_reset_on_drop)]
        }),
        serde_json::json!({
            "id": "trust_score",
            "name": "Trust Score 信誉引擎",
            "category": "智能防御",
            "description": "IP 双向信誉评估——PASS 加分、DROP 减分，动态调制速率阈值。高信誉 IP 自动放宽限速。",
            "enabled": rt.trust_enabled,
            "stats_key": None::<String>,
            "editable_fields": [field_switch("enabled", "启用 Trust Score", rt.trust_enabled)]
        }),
        serde_json::json!({
            "id": "danger_signal",
            "name": "Danger Signal 危险监测",
            "category": "智能防御",
            "description": "实时监测 CPU/内存/DPS 异常，自动提高全局防御等级（正常→警戒→危险）。",
            "enabled": rt.danger_level > 0,
            "stats_key": None::<String>,
            "editable_fields": [field_readonly("danger_level", "当前等级", serde_json::json!(rt.danger_level))]
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

fn field_readonly(id: &str, label: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"id": id, "type": "readonly", "label": label, "value": value})
}

async fn patch_config_handler(
    State(state): State<Arc<WebState>>,
    Json(patch): Json<RuntimeConfigPatch>,
) -> Result<&'static str, ApiError> {
    state
        .control
        .patch_runtime(patch)
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("配置已更新")
}

async fn reload_config_handler(
    State(state): State<Arc<WebState>>,
) -> Result<&'static str, ApiError> {
    state
        .control
        .reload_config_file()
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("配置已从文件重新加载")
}

async fn block_ip_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<BlockIpReq>,
) -> Result<&'static str, ApiError> {
    state
        .control
        .block_ip(&req.ip, req.duration_s)
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已封禁")
}

async fn unblock_ip_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<UnblockIpReq>,
) -> Result<&'static str, ApiError> {
    state
        .control
        .unblock_ip(&req.ip)
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已解封")
}

async fn allow_cidr_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<AllowCidrReq>,
) -> Result<&'static str, ApiError> {
    state
        .control
        .allow_cidr(&req.cidr)
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已加入白名单")
}

async fn disallow_cidr_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<DisallowCidrReq>,
) -> Result<&'static str, ApiError> {
    state
        .control
        .disallow_cidr(&req.cidr)
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("已移除白名单")
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    filter: Option<String>,
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

/// 趋势图用精简数据点：只保留 Dashboard 趋势图实际消费的字段，
/// 去掉 total_*、top_attackers / port_dropped 等冗余 HashMap，
/// 显著降低首屏 payload 大小和前端渲染耗时。
#[derive(Serialize)]
struct TrafficSeriesPoint {
    timestamp: u64,
    blacklist_blocked: u64,
    rate_limited: u64,
    syn_flood_blocked: u64,
    l7_blocked: u64,
    adaptive_blocked: u64,
    udp_flood_blocked: u64,
    icmp_flood_blocked: u64,
    geoip_blocked: u64,
    dps: Option<u64>,
    pps: Option<u64>,
    has_data: bool,
}

impl From<&crate::timeseries::MetricPoint> for TrafficSeriesPoint {
    fn from(p: &crate::timeseries::MetricPoint) -> Self {
        Self {
            timestamp: p.timestamp,
            blacklist_blocked: p.blacklist_blocked,
            rate_limited: p.rate_limited,
            syn_flood_blocked: p.syn_flood_blocked,
            l7_blocked: p.l7_blocked,
            adaptive_blocked: p.adaptive_blocked,
            udp_flood_blocked: p.udp_flood_blocked,
            icmp_flood_blocked: p.icmp_flood_blocked,
            geoip_blocked: p.geoip_blocked,
            dps: p.dps,
            pps: p.pps,
            has_data: p.has_data,
        }
    }
}

async fn metrics_series_handler(
    State(state): State<Arc<WebState>>,
    Query(q): Query<SeriesQuery>,
) -> Json<serde_json::Value> {
    let series = state.stats.timeseries.read().await.snapshot(q.duration_s);
    let slim: Vec<TrafficSeriesPoint> = series.iter().map(|p| p.into()).collect();
    Json(serde_json::json!({ "series": slim }))
}

async fn list_port_acl_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await;
    Json(serde_json::json!({ "items": rt.port_acl }))
}

async fn set_port_acl_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SetPortAclReq>,
) -> Result<&'static str, ApiError> {
    if req.items.len() > 128 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "too many port_acl entries (max 128)",
        ));
    }
    state
        .control
        .set_port_acl(req.items)
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
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
) -> Result<&'static str, ApiError> {
    if req.projects.len() > 256 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "too many protection projects (max 256)",
        ));
    }
    state
        .control
        .set_protection_projects(req.projects)
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("防护项目已更新")
}

async fn list_l7_patterns_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let rt = state.control.runtime.read().await;
    Json(serde_json::json!({ "patterns": rt.l7_scan.patterns }))
}

async fn set_l7_patterns_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SetL7PatternsReq>,
) -> Result<&'static str, ApiError> {
    if req.patterns.len() > 16 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "too many L7 patterns (max 16)",
        ));
    }
    state
        .control
        .set_l7_patterns(req.patterns)
        .await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("L7 指纹已更新")
}

async fn reload_geoip_handler(
    State(state): State<Arc<WebState>>,
) -> Result<&'static str, ApiError> {
    state
        .control
        .reload_geoip()
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("GeoIP 已重新加载")
}

async fn sync_threat_intel_handler(State(state): State<Arc<WebState>>) -> &'static str {
    let feeds = state
        .control
        .runtime
        .read()
        .await
        .threat_intel_feeds
        .clone();
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

async fn hub_status_handler(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let cfg = &state.control.hub_config;
    let connected = state
        .control
        .hub_connected
        .load(std::sync::atomic::Ordering::Relaxed);
    let active_url = state
        .control
        .hub_active_url
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    Json(serde_json::json!({
        "enabled": cfg.enabled,
        "connected": connected,
        "active_url": active_url,
        "node_name": cfg.node_name,
        "urls": cfg.urls,
    }))
}

fn hub_active_url(cfg: &crate::config::HubConfig) -> String {
    cfg.urls
        .first()
        .cloned()
        .unwrap_or_else(|| "http://localhost:9930".to_string())
        .trim_end_matches('/')
        .to_string()
}

async fn hub_proxy(
    state: &WebState,
    path: &str,
    query: Option<&str>,
) -> Result<Response, ApiError> {
    let cfg = &state.control.hub_config;
    if !cfg.enabled || cfg.token.is_empty() {
        return Err(api_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "hub not configured",
        ));
    }
    let mut url = format!("{}{}", hub_active_url(cfg), path);
    if let Some(q) = query {
        url.push('?');
        url.push_str(q);
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", cfg.token))
        .send()
        .await
        .map_err(|e| api_err(StatusCode::BAD_GATEWAY, e.to_string()))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| api_err(StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok((status, body).into_response())
}

async fn hub_proxy_stats_handler(
    State(state): State<Arc<WebState>>,
    request: Request,
) -> Result<Response, ApiError> {
    hub_proxy(&state, "/api/v1/stats", request.uri().query()).await
}

async fn hub_proxy_nodes_handler(
    State(state): State<Arc<WebState>>,
    request: Request,
) -> Result<Response, ApiError> {
    hub_proxy(&state, "/api/v1/nodes", request.uri().query()).await
}

async fn hub_proxy_policies_handler(
    State(state): State<Arc<WebState>>,
    request: Request,
) -> Result<Response, ApiError> {
    hub_proxy(&state, "/api/v1/policies", request.uri().query()).await
}

async fn audit_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entries = state
        .auditor
        .list(10_000)
        .await
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let filter_text = q.filter.as_deref().map(|s| s.to_lowercase());
    let ip_filter = q.ip.as_deref().map(|s| s.to_lowercase());
    let action_filter = q.action.as_deref().map(|s| s.to_lowercase());

    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            if let Some(ft) = &filter_text {
                let hay = format!(
                    "{} {} {} {}",
                    e.timestamp,
                    e.actor,
                    serde_json::to_string(&e.action).unwrap_or_default(),
                    serde_json::to_string(&e.detail).unwrap_or_default()
                )
                .to_lowercase();
                if !hay.contains(ft) {
                    return false;
                }
            }
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
        .collect::<Vec<_>>();

    let total = filtered.len();

    let paged: Vec<_> = filtered
        .into_iter()
        .rev()
        .skip(q.offset)
        .take(q.limit)
        .collect();

    Ok(Json(
        serde_json::json!({ "entries": paged, "total": total }),
    ))
}

async fn audit_stream_handler(
    State(state): State<Arc<WebState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.auditor.subscribe();
    let stream = BroadcastStream::new(rx).map(|result| match result {
        Ok(entry) => {
            let data = serde_json::to_string(&entry).unwrap_or_default();
            Ok(Event::default().event("audit").data(data))
        }
        Err(_) => Ok(Event::default().event("ping").data("")),
    });
    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

#[derive(Deserialize)]
struct PacketQuery {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    protocol: Option<u8>,
    #[serde(default)]
    action: Option<u8>,
    #[serde(default)]
    rule: Option<u16>,
    #[serde(default = "default_packet_limit")]
    limit: usize,
}

fn default_packet_limit() -> usize {
    100
}

/// 查询采样包日志。
async fn packets_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<PacketQuery>,
) -> Json<serde_json::Value> {
    let query = PacketLogQuery {
        ip: q.ip,
        port: q.port,
        protocol: q.protocol,
        action: q.action,
        rule: q.rule,
        from_ns: None,
        to_ns: None,
        limit: q.limit.min(1000),
    };
    let entries = state.packet_log.query(&query);
    Json(serde_json::json!({
        "entries": entries,
        "count": entries.len(),
    }))
}

#[derive(Deserialize)]
struct IpDetailQuery {
    ip: String,
}

#[derive(Serialize)]
struct IpPortCount {
    port: u16,
    count: u64,
}

#[derive(Serialize)]
struct IpDetailResponse {
    ip: String,
    blacklisted: bool,
    hit_count: u64,
    trust_score: u32,
    trust_level: u8,
    drop_count: u64,
    pass_count: u64,
    recent_samples: Vec<crate::packet_log::PacketSampleEntry>,
    top_ports: Vec<IpPortCount>,
}

/// 查询指定 IP 的实时状态：黑名单、信誉分、最近采样包、被攻击端口分布。
async fn ip_detail_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<IpDetailQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let key = parse_ip(&q.ip).map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;

    let (blacklisted, hit_count, trust_score, trust_level) = {
        let mut guard = state.control.ebpf.lock().await;

        let (blacklisted, hit_count) = {
            let blacklist: LruHashMap<_, IpKey, BlockEntry> = guard
                .map_mut("BLACKLIST")
                .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "BLACKLIST map not found"))?
                .try_into()
                .map_err(|e| {
                    api_err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("BLACKLIST map: {}", e),
                    )
                })?;
            match blacklist.get(&key, 0) {
                Ok(entry) => (true, entry.hit_count as u64),
                Err(_) => (false, 0),
            }
        };

        let (trust_score, trust_level) = match guard.map_mut("TRUST_MAP") {
            Some(m) => match LruHashMap::<_, IpKey, TrustEntry>::try_from(m) {
                Ok(trust_map) => match trust_map.get(&key, 0) {
                    Ok(entry) => ((entry.trust_score / 10).min(100), entry.level),
                    Err(_) => (50, 0),
                },
                Err(e) => {
                    tracing::debug!("failed to open TRUST_MAP: {}", e);
                    (50, 0)
                }
            },
            None => (50, 0),
        };

        (blacklisted, hit_count, trust_score, trust_level)
    };

    let samples = state.packet_log.query(&PacketLogQuery {
        ip: Some(q.ip.clone()),
        port: None,
        protocol: None,
        action: None,
        rule: None,
        from_ns: None,
        to_ns: None,
        limit: 100,
    });

    let mut drop_count = 0u64;
    let mut pass_count = 0u64;
    let mut port_counts: HashMap<u16, u64> = HashMap::new();
    for s in &samples {
        if s.action == 0 {
            drop_count += 1;
        } else {
            pass_count += 1;
        }
        *port_counts.entry(s.dst_port).or_insert(0) += 1;
    }
    let mut top_ports: Vec<IpPortCount> = port_counts
        .into_iter()
        .map(|(port, count)| IpPortCount { port, count })
        .collect();
    top_ports.sort_by_key(|p| std::cmp::Reverse(p.count));
    top_ports.truncate(10);

    let resp = IpDetailResponse {
        ip: q.ip,
        blacklisted,
        hit_count,
        trust_score,
        trust_level,
        drop_count,
        pass_count,
        recent_samples: samples,
        top_ports,
    };
    Ok(Json(serde_json::to_value(resp).unwrap_or_default()))
}

#[derive(Deserialize)]
struct IpSeriesQuery {
    ip: String,
    #[serde(default = "default_series_duration")]
    duration_s: u64,
}

#[derive(Serialize)]
struct IpSeriesPoint {
    timestamp: u64,
    drop_count: Option<u64>,
    pass_count: Option<u64>,
}

/// 将指定 IP 的采样包日志按 1 分钟桶聚合，用于详情页趋势图。
async fn ip_series_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<IpSeriesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let key = parse_ip(&q.ip).map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let _ = key;

    let duration_s = q.duration_s.clamp(60, 86400);
    let now_ns = crate::time::monotonic_ns();
    let from_ns = now_ns.saturating_sub(duration_s * 1_000_000_000);

    let samples = state.packet_log.query(&PacketLogQuery {
        ip: Some(q.ip.clone()),
        port: None,
        protocol: None,
        action: None,
        rule: None,
        from_ns: Some(from_ns),
        to_ns: None,
        limit: 10000,
    });

    // 将 eBPF 单调时钟转换为 wall-clock 秒，与 /api/metrics/series 保持一致。
    let wall_now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i128;
    let mono_now_ns = now_ns as i128;
    let offset_ns = wall_now_ns - mono_now_ns;

    let mut buckets: HashMap<u64, (u64, u64)> = HashMap::new();
    for s in &samples {
        let wall_ts_ns = (s.timestamp_ns as i128 + offset_ns).max(0) as u64;
        let minute = wall_ts_ns / 60_000_000_000;
        let entry = buckets.entry(minute).or_insert((0, 0));
        if s.action == 0 {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }

    let start_minute = ((from_ns as i128 + offset_ns).max(0) as u64) / 60_000_000_000;
    let end_minute = (wall_now_ns as u64) / 60_000_000_000;
    let mut points = Vec::with_capacity(((end_minute - start_minute) + 1) as usize);
    for minute in start_minute..=end_minute {
        let ts = minute * 60;
        let (drop_count, pass_count) = match buckets.get(&minute) {
            Some(&(d, p)) => (Some(d), Some(p)),
            None => (None, None),
        };
        points.push(IpSeriesPoint {
            timestamp: ts,
            drop_count,
            pass_count,
        });
    }

    Ok(Json(serde_json::json!({ "ip": q.ip, "series": points })))
}

/// 返回最近攻击事件（DROP 事件流）。
async fn attack_events_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Json<serde_json::Value> {
    let events: Vec<serde_json::Value> = state
        .stats
        .attack_events(q.limit.min(200))
        .into_iter()
        .map(|e| {
            let src_ip = match eshield_common::IpFamily::from_u8(e.family) {
                Some(eshield_common::IpFamily::Ipv4) => {
                    let octets = [e.src_ip[12], e.src_ip[13], e.src_ip[14], e.src_ip[15]];
                    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
                }
                Some(eshield_common::IpFamily::Ipv6) => {
                    crate::ip::format_ip_key(&eshield_common::IpKey::from_ipv6(e.src_ip))
                }
                None => "unknown".to_string(),
            };
            let rule_name = match e.rule_id {
                eshield_common::rules::BLACKLIST => "黑名单",
                eshield_common::rules::RATE_LIMIT => "速率限制",
                eshield_common::rules::SYN_FLOOD => "SYN Flood",
                eshield_common::rules::L7_PATTERN => "L7 指纹",
                eshield_common::rules::ADAPTIVE => "自适应",
                eshield_common::rules::PORT_ACL => "端口 ACL",
                eshield_common::rules::UDP_FLOOD => "UDP Flood",
                eshield_common::rules::ICMP_FLOOD => "ICMP Flood",
                eshield_common::rules::GEOIP => "GeoIP",
                eshield_common::rules::THREAT_INTEL => "威胁情报",
                _ => "未知",
            };
            serde_json::json!({
                "timestamp_ns": e.timestamp_ns,
                "src_ip": src_ip,
                "protocol": e.protocol,
                "rule_id": e.rule_id,
                "rule_name": rule_name,
                "dst_port": e.dst_port,
            })
        })
        .collect();

    Json(serde_json::json!({
        "events": events,
        "count": events.len(),
    }))
}

async fn attacker_series_handler(
    State(state): State<Arc<WebState>>,
    axum::extract::Query(q): axum::extract::Query<AttackerSeriesQuery>,
) -> Json<serde_json::Value> {
    let series = state.stats.timeseries.read().await.snapshot(q.duration_s);
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

    let mut top_ports: Vec<PortDrop> = stats
        .port_dropped
        .iter()
        .map(|entry| PortDrop {
            port: *entry.key(),
            count: entry.value().load(Ordering::Relaxed),
        })
        .collect();
    top_ports.sort_by_key(|p| std::cmp::Reverse(p.count));
    top_ports.truncate(10);

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
        geoip_blocked: stats.geoip_blocked.load(Ordering::Relaxed),
        tcp_rst_sent: stats.tcp_rst_sent.load(Ordering::Relaxed),
        tcp_rst_fail: stats.tcp_rst_fail.load(Ordering::Relaxed),
        tcp_rst_attempt: stats.tcp_rst_attempt.load(Ordering::Relaxed),
        tcp_dropped: stats.tcp_dropped.load(Ordering::Relaxed),
        udp_dropped: stats.udp_dropped.load(Ordering::Relaxed),
        icmp_dropped: stats.icmp_dropped.load(Ordering::Relaxed),
        other_dropped: stats.other_dropped.load(Ordering::Relaxed),
        top_attackers,
        top_ports,
        trust_trusted: stats.trust_trusted.load(Ordering::Relaxed),
        trust_neutral: stats.trust_neutral.load(Ordering::Relaxed),
        trust_suspicious: stats.trust_suspicious.load(Ordering::Relaxed),
        trust_malicious: stats.trust_malicious.load(Ordering::Relaxed),
        danger_level: stats.danger_level.load(Ordering::Relaxed),
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
         # HELP eshield_geoip_blocked_total GeoIP blocked packets\n\
         # TYPE eshield_geoip_blocked_total counter\n\
         eshield_geoip_blocked_total{{interface=\"{}\"}} {}\n\n\
         # HELP eshield_dropped_by_protocol_total Dropped packets by IP protocol\n\
         # TYPE eshield_dropped_by_protocol_total counter\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"tcp\"}} {}\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"udp\"}} {}\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"icmp\"}} {}\n\
         eshield_dropped_by_protocol_total{{interface=\"{}\",protocol=\"other\"}} {}\n",
        interface,
        stats.total_dropped,
        interface,
        stats.total_passed,
        interface,
        stats.blacklist_blocked,
        interface,
        stats.rate_limited,
        interface,
        stats.syn_flood_blocked,
        interface,
        stats.l7_blocked,
        interface,
        stats.adaptive_blocked,
        interface,
        stats.udp_flood_blocked,
        interface,
        stats.icmp_flood_blocked,
        interface,
        stats.geoip_blocked,
        interface,
        tcp,
        interface,
        udp,
        interface,
        icmp,
        interface,
        other,
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

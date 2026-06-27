use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
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
        .route("/ready", get(health::ready_handler))
        .route("/challenge", get(challenge_handler))
        .route("/api/challenge/pass", post(challenge_pass_handler))
        .with_state(state.clone());

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
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let app = public.merge(protected);

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

/// Challenge 签名密钥，用于防止 nonce 伪造（硬编码，生产环境应使用配置或随机启动密钥）。
const CHALLENGE_SECRET: u64 = 0x5f37_9a21_b4cd_8e01;

async fn challenge_handler() -> Html<String> {
    let a = rand::random::<u64>() % 10_000;
    let b = rand::random::<u64>() % 10_000;
    let sig = a ^ b ^ CHALLENGE_SECRET;
    let nonce = format!("{}:{}:{}", a, b, sig);
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>eShield Security Challenge</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1rem; }}
    h1 {{ font-size: 1.5rem; }}
    input, button {{ width: 100%; padding: .6rem; margin: .4rem 0; box-sizing: border-box; }}
    #result {{ margin-top: 1rem; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>eShield Security Challenge</h1>
  <p>您的请求被 WAF Challenge 规则拦截。请完成下方验证以获取临时访问权限。</p>
  <form id="challenge-form">
    <input type="hidden" id="nonce" value="{nonce}">
    <label for="ip">IP 地址</label>
    <input type="text" id="ip" placeholder="10.0.0.2" required>
    <input type="hidden" id="answer" value="">
    <button type="submit">验证</button>
  </form>
  <div id="result"></div>
  <script>
    const nonceEl = document.getElementById('nonce');
    const answerEl = document.getElementById('answer');
    const [a, b] = nonceEl.value.split(':');
    answerEl.value = (BigInt(a) + BigInt(b)).toString();

    document.getElementById('challenge-form').addEventListener('submit', async function(e) {{
      e.preventDefault();
      const ip = document.getElementById('ip').value;
      const answer = answerEl.value;
      const res = await fetch('/api/challenge/pass', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ip, nonce: nonceEl.value, answer}})
      }});
      const text = await res.text();
      document.getElementById('result').textContent = (res.ok ? '✅ ' : '❌ ') + text;
    }});
  </script>
</body>
</html>"#
    ))
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
        waf_blocked: stats.waf_blocked.load(std::sync::atomic::Ordering::Relaxed),
        geoip_blocked: stats.geoip_blocked.load(std::sync::atomic::Ordering::Relaxed),
        challenge_issued: stats
            .challenge_issued
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

use crate::{
    auth::{auth_layer, NodeIdentity},
    models::{
        DeletedPolicies, NodeHeartbeat, NodesResponse, PolicyDelete, PolicyPull, PolicyPush,
        RulesResponse, StatsResponse,
    },
    state::AppState,
    time::now_ns,
};
use axum::{
    extract::{ConnectInfo, Extension, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;

/// 单次删除请求允许的最大 IP 数，避免 1MB 请求体塞入数万条策略导致长事务。
const MAX_DELETE_IPS: usize = 10_000;
/// node_name 最大长度，防止伪造超长名字撑大注册表/限流桶。
const MAX_NODE_NAME_LEN: usize = 128;

#[derive(Deserialize)]
struct PullParams {
    since: u64,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct DeletedParams {
    since: u64,
    limit: Option<usize>,
}

/// Hub 侧请求日志（与节点侧 web.rs 的 request_logger 对齐，便于统一排障）。
async fn request_logger(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        event_type = "http",
        component = "hub",
        client_ip = %addr.ip(),
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        elapsed_ms = start.elapsed().as_millis() as u64,
        "hub http request"
    );
    response
}

pub fn router(state: Arc<AppState>) -> Router {
    let auth = state.auth.clone();
    let public = Router::new()
        .route("/", get(index_handler))
        .route("/login", get(login_handler))
        .layer(middleware::from_fn(request_logger))
        .with_state(Arc::clone(&state));

    let protected = Router::new()
        .route(
            "/api/v1/policies",
            post(push_policies)
                .get(pull_policies)
                .delete(delete_policies),
        )
        .route("/api/v1/policies/deleted", get(deleted_policies))
        .route("/api/v1/rules", get(get_rules).post(set_rules))
        .route("/api/v1/nodes/heartbeat", post(heartbeat))
        .route("/api/v1/nodes", get(list_nodes))
        .route("/api/v1/stats", get(stats))
        .layer(middleware::from_fn_with_state(auth, auth_layer))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(middleware::from_fn(request_logger))
        .with_state(state);

    public.merge(protected)
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn login_handler() -> Html<&'static str> {
    Html(include_str!("login.html"))
}

async fn push_policies(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<NodeIdentity>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(push): Json<PolicyPush>,
) -> Result<impl IntoResponse, StatusCode> {
    // 节点专属 token 时以认证身份为准，防止请求体伪造 node_name。
    let node_name = identity.0.unwrap_or_else(|| push.node_name.clone());
    if !state.rate_limiter.check(&node_name, now_ns()) {
        tracing::warn!(%addr, node = %node_name, "rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    match state.store.merge(&node_name, &push.policies) {
        Ok(merged) => {
            tracing::info!(
                event_type = "hub_audit",
                actor = %node_name,
                action = "push_policies",
                count = push.policies.len(),
                merged,
                %addr,
                "hub policy push"
            );
            Ok(Json(json!({ "merged": merged })))
        }
        Err(err) => {
            tracing::error!(%addr, node = %node_name, "failed to merge policies: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn pull_policies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PullParams>,
) -> Result<Json<PolicyPull>, StatusCode> {
    // 限制单次拉取上限，避免单个客户端请求把整个策略库加载进内存。
    let limit = params.limit.unwrap_or(1000).clamp(1, 10_000);
    match state.store.query_since(params.since, limit) {
        Ok((policies, cursor)) => Ok(Json(PolicyPull {
            policies,
            cursor: cursor.to_string(),
            deleted: Vec::new(),
            deleted_cursor: params.since.to_string(),
        })),
        Err(err) => {
            tracing::error!("failed to query policies: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<NodeIdentity>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(hb): Json<NodeHeartbeat>,
) -> StatusCode {
    let node_name = identity.0.unwrap_or(hb.node_name);
    if node_name.is_empty() || node_name.len() > MAX_NODE_NAME_LEN {
        tracing::warn!(%addr, len = node_name.len(), "rejected heartbeat: invalid node_name");
        return StatusCode::BAD_REQUEST;
    }
    // 心跳也走令牌桶：否则伪造大量 node_name 可以无成本撑大注册表与限流桶。
    if !state.rate_limiter.check(&node_name, now_ns()) {
        tracing::warn!(%addr, node = %node_name, "heartbeat rate limit exceeded");
        return StatusCode::TOO_MANY_REQUESTS;
    }
    tracing::debug!(%addr, node = %node_name, "heartbeat received");
    state.registry.heartbeat(node_name, now_ns());
    StatusCode::OK
}

async fn list_nodes(State(state): State<Arc<AppState>>) -> Result<Json<NodesResponse>, StatusCode> {
    let nodes = state.registry.list(now_ns(), state.node_timeout_ns);
    Ok(Json(NodesResponse { nodes }))
}

async fn stats(State(state): State<Arc<AppState>>) -> Result<Json<StatsResponse>, StatusCode> {
    let nodes = state.registry.list(now_ns(), state.node_timeout_ns);
    let policy_count = state.store.count().map_err(|err| {
        tracing::error!("failed to count policies: {err}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(StatsResponse {
        policy_count,
        node_count: nodes.len(),
        online_node_count: nodes.iter().filter(|n| n.online).count(),
    }))
}

async fn delete_policies(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<NodeIdentity>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<PolicyDelete>,
) -> Result<impl IntoResponse, StatusCode> {
    let node_name = identity.0.unwrap_or_else(|| req.node_name.clone());
    if !state.rate_limiter.check(&node_name, now_ns()) {
        tracing::warn!(%addr, node = %node_name, "rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if req.ips.len() > MAX_DELETE_IPS {
        tracing::warn!(%addr, node = %node_name, count = req.ips.len(), "rejected delete: too many ips");
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // 批量删除：单个写事务完成，避免逐 IP 各开一次事务造成的 fsync 放大。
    match state.store.delete_policies(&req.ips) {
        Ok(removed) => {
            tracing::info!(
                event_type = "hub_audit",
                actor = %node_name,
                action = "delete_policies",
                requested = req.ips.len(),
                removed,
                %addr,
                "hub policy delete"
            );
            Ok(Json(json!({ "removed": removed })))
        }
        Err(err) => {
            tracing::error!(%addr, node = %node_name, "failed to delete policies: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn deleted_policies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DeletedParams>,
) -> Result<Json<DeletedPolicies>, StatusCode> {
    let limit = params.limit.unwrap_or(1000).clamp(1, 10_000);
    match state.store.query_tombstones_since(params.since, limit) {
        Ok((ips, cursor)) => Ok(Json(DeletedPolicies {
            ips,
            cursor: cursor.to_string(),
        })),
        Err(err) => {
            tracing::error!("failed to query tombstones: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_rules(State(state): State<Arc<AppState>>) -> Result<Json<RulesResponse>, StatusCode> {
    match state.store.get_rules() {
        Ok(rules) => Ok(Json(RulesResponse { rules })),
        Err(err) => {
            tracing::error!("failed to get rules: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn set_rules(
    State(state): State<Arc<AppState>>,
    Json(bundle): Json<crate::models::RuleBundle>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.store.set_rules(&bundle) {
        Ok(()) => Ok(Json(json!({ "updated_at_ns": bundle.updated_at_ns }))),
        Err(err) => {
            tracing::error!("failed to set rules: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

use crate::{
    auth::auth_layer,
    models::{
        DeletedPolicies, NodeHeartbeat, NodesResponse, PolicyDelete, PolicyPull, PolicyPush,
        RulesResponse, StatsResponse,
    },
    state::AppState,
    time::now_ns,
};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    middleware::{self},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;

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

pub fn router(state: Arc<AppState>) -> Router {
    let auth = state.auth.clone();
    let public = Router::new()
        .route("/", get(index_handler))
        .with_state(Arc::clone(&state));

    let protected = Router::new()
        .route("/api/v1/policies", post(push_policies).get(pull_policies).delete(delete_policies))
        .route("/api/v1/policies/deleted", get(deleted_policies))
        .route("/api/v1/rules", get(get_rules).post(set_rules))
        .route("/api/v1/nodes/heartbeat", post(heartbeat))
        .route("/api/v1/nodes", get(list_nodes))
        .route("/api/v1/stats", get(stats))
        .layer(middleware::from_fn_with_state(auth, auth_layer))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state);

    public.merge(protected)
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn push_policies(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(push): Json<PolicyPush>,
) -> Result<impl IntoResponse, StatusCode> {
    if !state.rate_limiter.check(&push.node_name, now_ns()) {
        tracing::warn!(%addr, node = %push.node_name, "rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    match state.store.merge(&push.node_name, &push.policies) {
        Ok(merged) => Ok(Json(json!({ "merged": merged }))),
        Err(err) => {
            tracing::error!(%addr, node = %push.node_name, "failed to merge policies: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn pull_policies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PullParams>,
) -> Result<Json<PolicyPull>, StatusCode> {
    let limit = params.limit.unwrap_or(1000);
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(hb): Json<NodeHeartbeat>,
) -> StatusCode {
    tracing::debug!(%addr, node = %hb.node_name, "heartbeat received");
    state.registry.heartbeat(hb.node_name, now_ns());
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<PolicyDelete>,
) -> Result<impl IntoResponse, StatusCode> {
    if !state.rate_limiter.check(&req.node_name, now_ns()) {
        tracing::warn!(%addr, node = %req.node_name, "rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let mut removed = 0usize;
    for ip in &req.ips {
        match state.store.delete_policy(ip) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(err) => {
                tracing::error!(%addr, node = %req.node_name, "failed to delete policy: {err}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    Ok(Json(json!({ "removed": removed })))
}

async fn deleted_policies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DeletedParams>,
) -> Result<Json<DeletedPolicies>, StatusCode> {
    let limit = params.limit.unwrap_or(1000);
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

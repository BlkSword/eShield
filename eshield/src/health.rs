use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::web::WebState;

/// `/healthz` — 进程存活检查
pub async fn healthz_handler() -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

/// `/ready` — 服务就绪检查：验证 eBPF 程序已加载。
pub async fn ready_handler(State(state): axum::extract::State<Arc<WebState>>) -> Response {
    let guard = state.control.ebpf.lock().await;
    // 检查 eBPF 程序是否已加载（load 成功后 program 即存在）。
    let ready = guard.program("eshield").is_some();
    drop(guard);

    if ready {
        (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not ready", "error": "eBPF program not loaded" })),
        )
            .into_response()
    }
}

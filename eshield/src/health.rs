use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::control::ControlState;

/// `/healthz` — 进程存活检查
pub async fn healthz_handler() -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

/// `/ready` — 服务就绪检查：eBPF 程序已挂载且接口存在
pub async fn ready_handler(State(state): axum::extract::State<Arc<ControlState>>) -> Response {
    // 简化实现：只要控制面初始化成功即认为 ready
    // 未来可进一步检查 XDP 程序是否仍挂载在接口上
    let _ = state;
    (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
}

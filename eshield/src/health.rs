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

/// `/ready` — 服务就绪检查。
///
/// v0.4.8：不再只看"程序对象是否存在"，而是看**内核里是否真的挂着我们的 XDP 程序**
/// （由启动流程与后台巡检任务维护 `stats.xdp_attached`）。程序被驱动重置、被外部
/// 摘掉或重挂失败时这里返回 503，负载均衡/监控能立刻发现"防护已失效"。
pub async fn ready_handler(State(state): axum::extract::State<Arc<WebState>>) -> Response {
    use std::sync::atomic::Ordering;

    let attached = state.stats.xdp_attached.load(Ordering::Relaxed);
    let mode = state.stats.xdp_mode_str();

    if attached {
        (
            StatusCode::OK,
            Json(json!({ "status": "ready", "xdp_attached": true, "xdp_mode": mode })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not ready",
                "xdp_attached": false,
                "xdp_mode": mode,
                "error": "XDP program is not attached to the interface",
            })),
        )
            .into_response()
    }
}

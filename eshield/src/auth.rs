use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// 认证状态：保存可选的 API Token。
#[derive(Clone, Debug, Default)]
pub struct AuthState {
    pub token: Option<Arc<str>>,
}

impl AuthState {
    pub fn new(token: Option<String>) -> Self {
        Self {
            token: token.map(|s| Arc::from(s.into_boxed_str())),
        }
    }

}

/// axum 中间件：若配置了 Token，则校验请求头中的 Bearer Token。
pub async fn auth_middleware(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    match state.token {
        None => next.run(request).await,
        Some(ref token) => {
            let header = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());

            let provided = header.and_then(|h| h.strip_prefix("Bearer "));
            if provided.map(|t| constant_time_eq(token, t)).unwrap_or(false) {
                next.run(request).await
            } else {
                (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
        }
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// Re-export axum extract State to keep imports clean in callers.
pub use axum::extract::State;

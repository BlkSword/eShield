use axum::{
    body::Body,
    extract::Request,
    http::{header::ACCEPT, StatusCode},
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

    pub fn verify(&self, provided: &str) -> bool {
        match &self.token {
            None => false,
            Some(token) => constant_time_eq(token, provided),
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
                // 对未认证的 Dashboard 根路径浏览器请求重定向到登录页，提升体验。
                let is_html_root = request.uri().path() == "/"
                    && request
                        .headers()
                        .get(ACCEPT)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.contains("text/html"))
                        .unwrap_or(false);
                if is_html_root {
                    return Response::builder()
                        .status(StatusCode::FOUND)
                        .header("Location", "/login")
                        .body(Body::empty())
                        .unwrap()
                        .into_response();
                }
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

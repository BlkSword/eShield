use axum::{
    body::Body,
    extract::Request,
    http::{header::ACCEPT, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// 认证状态：保存可选的 API Token，支持运行时重置。
#[derive(Clone, Debug, Default)]
pub struct AuthState {
    token: Arc<RwLock<Option<Arc<str>>>>,
}

impl AuthState {
    pub fn new(token: Option<String>) -> Self {
        Self {
            token: Arc::new(RwLock::new(token.map(|s| Arc::from(s.into_boxed_str())))),
        }
    }

    pub async fn verify(&self, provided: &str) -> bool {
        let guard = self.token.read().await;
        match &*guard {
            None => false,
            Some(token) => constant_time_eq(token, provided),
        }
    }

    pub async fn get_token(&self) -> Option<String> {
        let guard = self.token.read().await;
        guard.as_ref().map(|s| s.to_string())
    }

    pub async fn set_token(&self, token: String) {
        let mut guard = self.token.write().await;
        *guard = Some(Arc::from(token.into_boxed_str()));
    }

    /// 生成新的随机访问令牌并返回。
    pub async fn reset_token(&self) -> String {
        let token = format!("{:032x}", rand::random::<u128>());
        self.set_token(token.clone()).await;
        token
    }
}

/// axum 中间件：仅对 Dashboard 根路径 `/` 的 HTML 请求强制校验 Token。
/// /api/*、/metrics、/login 等端点均放行，以便 CLI 无需 token 即可操作。
pub async fn auth_middleware(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    let token = state.get_token().await;
    let is_html_root = request.uri().path() == "/"
        && request
            .headers()
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("text/html"))
            .unwrap_or(false);

    match token {
        None => next.run(request).await,
        Some(_token) if !is_html_root => next.run(request).await,
        Some(token) => {
            let header = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());

            let provided = header.and_then(|h| h.strip_prefix("Bearer "));
            if provided.map(|t| constant_time_eq(&token, t)).unwrap_or(false) {
                next.run(request).await
            } else {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Body::empty())
                    .unwrap()
                    .into_response()
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

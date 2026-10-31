use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    http::{header::ACCEPT, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 访问角色（v0.5.0 RBAC-lite）：
/// - Admin：读写全部 API；
/// - Readonly：只允许 GET/HEAD（监控系统、只读大屏）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    Readonly,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Readonly => "readonly",
        }
    }
}

/// 认证状态：保存可选的 API Token（读写）与只读 Token，支持运行时重置。
#[derive(Clone, Debug, Default)]
pub struct AuthState {
    token: Arc<RwLock<Option<Arc<str>>>>,
    readonly_token: Arc<RwLock<Option<Arc<str>>>>,
}

impl AuthState {
    /// 同时配置读写 Token 与只读 Token（v0.5.0）。
    pub fn with_readonly(token: Option<String>, readonly: Option<String>) -> Self {
        // 空字符串 token 等价于未配置：否则外部请求可以用空 Cookie 绕过认证。
        let token = token.filter(|s| !s.is_empty());
        let readonly = readonly.filter(|s| !s.is_empty());
        Self {
            token: Arc::new(RwLock::new(token.map(|s| Arc::from(s.into_boxed_str())))),
            readonly_token: Arc::new(RwLock::new(readonly.map(|s| Arc::from(s.into_boxed_str())))),
        }
    }

    /// 返回该凭据对应的角色；未匹配任何 Token 时返回 None。
    pub async fn role_of(&self, provided: &str) -> Option<Role> {
        if provided.is_empty() {
            return None;
        }
        {
            let guard = self.token.read().await;
            if let Some(token) = &*guard {
                if constant_time_eq(token, provided) {
                    return Some(Role::Admin);
                }
            }
        }
        let guard = self.readonly_token.read().await;
        if let Some(token) = &*guard {
            if constant_time_eq(token, provided) {
                return Some(Role::Readonly);
            }
        }
        None
    }

    pub async fn verify(&self, provided: &str) -> bool {
        if provided.is_empty() {
            return false;
        }
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
        if token.is_empty() {
            return;
        }
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

/// axum 中间件：对非本机来源的请求强制校验 Token。
/// CLI 在本地运行时来源地址为 127.0.0.1/::1，无需 token；
/// 外部 Web 访问 `/`、所有 `/api/*` 及 `/metrics` 必须提供正确 Bearer Token。
pub async fn auth_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    // 本机请求直接放行，供 CLI 使用；但如果请求带有反向代理头，
    // 说明对端可能是同机 nginx/Caddy，此时必须按外部请求走 Token 校验，
    // 否则“127.0.0.1 免认证”会把所有经代理的外部流量变成免认证。
    let proxy_headers_present = request.headers().contains_key("x-forwarded-for")
        || request.headers().contains_key("x-real-ip")
        || request.headers().contains_key("forwarded");
    if addr.ip().is_loopback() && !proxy_headers_present {
        request.extensions_mut().insert(Role::Admin);
        return next.run(request).await;
    }

    let token = state.get_token().await;
    let is_html_root = request.uri().path() == "/"
        && request
            .headers()
            .get(ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("text/html"))
            .unwrap_or(false);

    match token {
        None => {
            // 未配置 Token：本机/外部均视为管理角色（兼容旧部署）
            request.extensions_mut().insert(Role::Admin);
            next.run(request).await
        }
        Some(_token) => {
            let header = request
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());

            let provided_from_header = header.and_then(|h| h.strip_prefix("Bearer "));

            let provided_from_cookie = request
                .headers()
                .get(axum::http::header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';').find_map(|cookie| {
                        let mut parts = cookie.trim().splitn(2, '=');
                        if parts.next()? == "eshield-token" {
                            parts.next()
                        } else {
                            None
                        }
                    })
                });

            let provided = provided_from_header.or(provided_from_cookie);
            let role = match provided {
                Some(t) => state.role_of(t).await,
                None => None,
            };
            if let Some(role) = role {
                // 只读 Token 只允许安全方法，避免监控凭据被拿来改配置。
                let method = request.method().clone();
                let safe = method == axum::http::Method::GET
                    || method == axum::http::Method::HEAD
                    || method == axum::http::Method::OPTIONS;
                if role == Role::Readonly && !safe && request.uri().path() != "/api/auth/logout" {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "read-only token: write operations are not permitted"
                        })),
                    )
                        .into_response();
                }
                request.extensions_mut().insert(role);
                next.run(request).await
            } else if is_html_root {
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Body::empty())
                    .unwrap()
                    .into_response()
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "Unauthorized" })),
                )
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

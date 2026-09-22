use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

/// Hub 认证：支持一个 master token（兼容旧部署）与多个“节点名 -> token”映射。
#[derive(Clone)]
pub struct HubAuth {
    master_token: String,
    node_tokens: HashMap<String, String>,
}

impl HubAuth {
    pub fn new(master_token: String, node_tokens: HashMap<String, String>) -> Self {
        Self {
            master_token,
            node_tokens,
        }
    }

    /// 认证成功返回：
    /// - `Some(None)`：master token（沿用请求体 node_name，兼容旧节点）；
    /// - `Some(Some(node))`：节点专属 token，后续以认证节点名为准；
    /// - `None`：认证失败。
    pub fn authenticate(&self, provided: Option<&str>) -> Option<Option<String>> {
        let token = provided.unwrap_or("");
        let token = token.strip_prefix("Bearer ").unwrap_or(token);
        if token.is_empty() {
            return None;
        }
        if constant_time_eq(token.as_bytes(), self.master_token.as_bytes()) {
            return Some(None);
        }
        let mut matched: Option<String> = None;
        for (node, node_token) in &self.node_tokens {
            if constant_time_eq(token.as_bytes(), node_token.as_bytes()) {
                matched = Some(node.clone());
            }
        }
        matched.map(Some)
    }
}

/// 认证后的节点身份，供 API handler 读取；`None` 表示 master token。
#[derive(Clone, Debug)]
pub struct NodeIdentity(pub Option<String>);

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub async fn auth_layer(
    State(auth): State<HubAuth>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    match auth.authenticate(header) {
        Some(identity) => {
            request.extensions_mut().insert(NodeIdentity(identity));
            Ok(next.run(request).await)
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> HubAuth {
        let mut node_tokens = HashMap::new();
        node_tokens.insert("node-a".to_string(), "token-a".to_string());
        HubAuth::new("master".to_string(), node_tokens)
    }

    #[test]
    fn master_token_returns_legacy_identity() {
        assert_eq!(auth().authenticate(Some("Bearer master")), Some(None));
    }

    #[test]
    fn node_token_returns_node_identity() {
        assert_eq!(
            auth().authenticate(Some("Bearer token-a")),
            Some(Some("node-a".to_string()))
        );
    }

    #[test]
    fn invalid_token_rejected() {
        assert_eq!(auth().authenticate(Some("Bearer nope")), None);
        assert_eq!(auth().authenticate(None), None);
    }
}

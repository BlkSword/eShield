use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct HubAuth {
    token: String,
}

impl HubAuth {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub fn verify(&self, provided: Option<&str>) -> bool {
        let token = provided.unwrap_or("");
        let token = token.strip_prefix("Bearer ").unwrap_or(token);
        token.as_bytes().ct_eq(self.token.as_bytes()).into()
    }
}

pub async fn auth_layer(
    State(auth): State<HubAuth>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());

    if auth.verify(header) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

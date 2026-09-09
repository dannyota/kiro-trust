//! Loopback HTTP surface (spec 5.1, 6.3).

pub mod error;
mod models;

use crate::server::error::ApiError;
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::Upstream;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_CONCURRENT: usize = 32;

pub struct AppState {
    pub tokens: Arc<TokenSource>,
    pub upstream: Arc<dyn Upstream>,
    pub local_token: SecretString,
    pub limiter: Arc<Semaphore>,
    /// Per-process salt for deriving Kiro conversation ids (Task 18).
    pub conversation_salt: [u8; 16],
}

fn presented_token(headers: &HeaderMap) -> Option<&str> {
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(t) = v.strip_prefix("Bearer ")
    {
        return Some(t.trim());
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

async fn require_token(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }
    let ok = presented_token(req.headers())
        .map(|t| {
            t.as_bytes()
                .ct_eq(state.local_token.expose_secret().as_bytes())
                .into()
        })
        .unwrap_or(false);
    if !ok {
        return ApiError::authentication("missing or invalid local token").into_response();
    }
    next.run(req).await
}

async fn health() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        "{\"status\":\"ok\"}",
    )
        .into_response()
}

async fn not_found() -> Response {
    ApiError::not_found("no such route").into_response()
}

async fn method_not_allowed() -> Response {
    ApiError::method_not_allowed().into_response()
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/models", get(models::get_models))
        .route("/v1/messages", post(placeholder_messages))
        .route("/v1/messages/count_tokens", post(placeholder_messages))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Replaced in Task 18.
async fn placeholder_messages() -> Response {
    ApiError::api_error("not implemented").into_response()
}

#[allow(dead_code)]
fn _assert_body_type(_: Body) {}

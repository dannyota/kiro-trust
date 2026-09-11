//! Loopback HTTP surface (spec 5.1, 6.3).

#[cfg(feature = "capture")]
pub mod capture;
pub mod count_tokens;
pub mod error;
pub mod messages;
mod models;
pub mod pump;
pub mod usage;

use crate::listener::ConnectionInfo;
use crate::server::error::ApiError;
use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
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
    pub usage: Arc<usage::UsageSummary>,
    /// Per-process salt for deriving Kiro conversation ids (Task 18).
    pub conversation_salt: [u8; 16],
    /// Developer-only payload capture (spec 8.3). `None` when no
    /// `--capture-dir` was given; the field itself does not exist unless
    /// built with the `capture` feature.
    #[cfg(feature = "capture")]
    pub capture: Option<Arc<capture::Capture>>,
}

fn presented_token(headers: &HeaderMap) -> Option<&str> {
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(t) = v.strip_prefix("Bearer ")
    {
        let t = t.trim();
        return if t.is_empty() { None } else { Some(t) };
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
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

/// Disarms the connection's header-read deadline (spec 6.3): once this runs,
/// `GuardedIo::poll_read` stops racing the timer for the rest of the
/// connection's lifetime. This is layered OUTSIDE `require_token` so it runs
/// even for an unauthenticated or otherwise-rejected request; the deadline
/// exists to bound how long an unparsed connection sits open, not to police
/// authentication, so it must disarm before `require_token` gets a chance to
/// reject anything.
///
/// Axum only invokes middleware after hyper has parsed a complete request on
/// the connection, which is exactly the signal spec 6.3 calls for and why
/// this is sound: it is never invoked for a connection that is still only
/// partway through its request line or headers.
///
/// The connect info is read as `Option<ConnectInfo<ConnectionInfo>>` and
/// this does nothing when it is absent. It is always absent in the 49+
/// existing router tests that call `oneshot` directly with no connect info,
/// and it would also be absent for any router served without
/// `into_make_service_with_connect_info`, so a required extractor here would
/// break both compiling tests and make an unauthenticated request
/// panic-prone. `build_router`'s signature is unchanged.
async fn headers_received(req: Request, next: Next) -> Response {
    if let Some(ConnectInfo(info)) = req.extensions().get::<ConnectInfo<ConnectionInfo>>() {
        info.header_deadline.disarm();
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

async fn usage(State(state): State<Arc<AppState>>) -> axum::Json<usage::UsageReport> {
    axum::Json(state.usage.snapshot())
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
        .route("/v1/usage", get(usage))
        .route("/v1/messages", post(messages::post_messages))
        .route(
            "/v1/messages/count_tokens",
            post(count_tokens::post_count_tokens),
        )
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        // Outside require_token (a later `.layer` call wraps, and therefore
        // runs before, an earlier one): the deadline must disarm even for a
        // request `require_token` goes on to reject (spec 6.3).
        .layer(middleware::from_fn(headers_received))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

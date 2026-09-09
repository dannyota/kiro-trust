//! The Anthropic error envelope (spec 5.6).

use axum::extract::rejection::BytesRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kiro_trust_kiro::{UpstreamError, UpstreamErrorKind};
use kiro_trust_protocol::sanitize::{self, MAX_MESSAGE_BYTES};
use serde_json::json;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub message: String,
}

impl ApiError {
    // Scrub before capping (spec 5.6), matching `kiro-trust-kiro`'s
    // `UpstreamError::new`: applying this here rather than only in
    // `failure_to_error` covers every error constructor, including ones
    // added later, and re-scrubbing a message that already went through
    // `parse_exception_message` is idempotent and harmless.
    fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        let message: String = message.into();
        let message = sanitize::scrub_identifiers(&message);
        let message = sanitize::cap(&message, MAX_MESSAGE_BYTES);
        ApiError {
            status,
            kind,
            message,
        }
    }
    pub fn invalid_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request_error", m)
    }
    pub fn authentication(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "authentication_error", m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found_error", m)
    }
    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "invalid_request_error",
            "method not allowed",
        )
    }
    pub fn rate_limit(m: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limit_error", m)
    }
    // The brief's interface (Task 17) fixes this method's name to
    // `api_error`, which is `ApiError` in snake_case: the lint's premise
    // does apply. The allow is deliberate, not a workaround for a false
    // positive.
    #[allow(clippy::self_named_constructors)]
    pub fn api_error(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "api_error", m)
    }
    // The real Anthropic API returns 413 `request_too_large` for a body over
    // the 32 MiB Messages API limit (spec 5.6), distinct from 400
    // `invalid_request_error`: a client can tell "retry with a smaller
    // request" from "your JSON is malformed".
    pub fn request_too_large(m: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large", m)
    }

    pub fn body(&self) -> serde_json::Value {
        json!({"type": "error", "error": {"type": self.kind, "message": self.message}})
    }
}

impl From<UpstreamError> for ApiError {
    fn from(e: UpstreamError) -> Self {
        let detail = match &e.exception_type {
            Some(t) if !e.message.is_empty() => format!("{t}: {}", e.message),
            Some(t) => t.clone(),
            None => e.message.clone(),
        };
        match e.kind {
            UpstreamErrorKind::Auth => {
                Self::authentication(format!("Kiro credential rejected: {detail}"))
            }
            UpstreamErrorKind::Throttled => {
                Self::rate_limit(format!("upstream throttled: {detail}"))
            }
            UpstreamErrorKind::Server
            | UpstreamErrorKind::Transport
            | UpstreamErrorKind::Protocol
            | UpstreamErrorKind::Client => Self::api_error(format!("upstream error: {detail}")),
        }
    }
}

/// `Bytes` rejects a request whose body is too large (or otherwise
/// unreadable) before a handler ever runs. Map it to the project's error
/// envelope instead of axum's plain-text default (spec 5.6).
impl From<BytesRejection> for ApiError {
    fn from(e: BytesRejection) -> Self {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self::request_too_large(format!(
                "request body exceeds the {}-byte limit",
                super::MAX_BODY_BYTES
            ))
        } else {
            Self::invalid_request("failed to read request body")
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = self.body().to_string();
        (
            self.status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response()
    }
}

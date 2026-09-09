//! The Anthropic error envelope (spec 5.6).

use axum::extract::rejection::BytesRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kiro_trust_kiro::{UpstreamError, UpstreamErrorKind};
use serde_json::json;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub message: String,
}

impl ApiError {
    fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            kind,
            message: message.into(),
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
            Self::invalid_request(format!(
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

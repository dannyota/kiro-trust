//! Upstream error classification (spec 5.6). Transcribed from kirocc
//! internal/kiroclient/aws_error.go.

use kiro_trust_protocol::sanitize::{self, MAX_MESSAGE_BYTES};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamErrorKind {
    /// 403 after a refresh attempt, or no usable credential.
    Auth,
    /// 429, ThrottlingException, TooManyRequestsException.
    Throttled,
    /// The exact `INSUFFICIENT_MODEL_CAPACITY` runtime marker.
    ModelCapacity,
    /// The exact `MONTHLY_REQUEST_COUNT` runtime marker: the monthly request
    /// allowance is used up. Never retried.
    AllowanceExhausted,
    /// 5xx, InternalServerException and friends.
    Server,
    /// Connection, TLS, timeout, redirect.
    Transport,
    /// A 200 that is not an event stream and not a known exception, or a bad frame.
    Protocol,
    /// Any other 4xx.
    Client,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("upstream {kind:?} (status {status:?}, {exception_type:?}): {message}")]
pub struct UpstreamError {
    pub kind: UpstreamErrorKind,
    pub status: Option<u16>,
    pub exception_type: Option<String>,
    /// Completed `net.post()` calls observed by this `generate()` call.
    pub attempts: u32,
    /// A normalized delay the local server may return to its caller.
    pub retry_after: Option<std::time::Duration>,
    /// Capped at 1 KiB; never carries request content.
    pub message: String,
}

impl UpstreamError {
    pub fn new(
        kind: UpstreamErrorKind,
        status: Option<u16>,
        exception_type: Option<String>,
        attempts: u32,
        retry_after: Option<std::time::Duration>,
        message: impl Into<String>,
    ) -> Self {
        let message: String = message.into();
        let message = sanitize::cap(&message, MAX_MESSAGE_BYTES);
        UpstreamError {
            kind,
            status,
            exception_type,
            attempts,
            retry_after,
            message,
        }
    }
}

const CAPACITY_MARKER: &[u8] = b"INSUFFICIENT_MODEL_CAPACITY";
const ALLOWANCE_MARKER: &[u8] = b"MONTHLY_REQUEST_COUNT";

fn contains(body: &[u8], marker: &[u8]) -> bool {
    body.windows(marker.len()).any(|window| window == marker)
}

/// Whether a bounded error body carries the exact monthly allowance marker
/// (spec 5.6).
pub fn is_allowance_exhausted(body: &[u8]) -> bool {
    contains(body, ALLOWANCE_MARKER)
}

/// Capacity outranks the allowance marker, and both outrank a plain 429
/// (spec 5.6).
pub fn classify_throttle(status: u16, body: &[u8]) -> UpstreamErrorKind {
    if contains(body, CAPACITY_MARKER) {
        UpstreamErrorKind::ModelCapacity
    } else if is_allowance_exhausted(body) {
        UpstreamErrorKind::AllowanceExhausted
    } else if status == 429 {
        UpstreamErrorKind::Throttled
    } else {
        UpstreamErrorKind::Server
    }
}

pub fn normalize_exception_type(raw: &str) -> String {
    let after_hash = raw.rsplit('#').next().unwrap_or(raw);
    after_hash
        .split(':')
        .next()
        .unwrap_or(after_hash)
        .to_string()
}

/// `__type`, `type`, or `code` from an AWS JSON 1.0 error body.
pub fn parse_exception_type(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let raw = ["__type", "type", "code"]
        .iter()
        .find_map(|k| v.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()))?;
    Some(normalize_exception_type(raw))
}

pub fn parse_exception_message(body: &[u8]) -> String {
    let raw = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();
    sanitize::scrub_identifiers(&raw)
}

pub fn is_retryable_exception(t: &str) -> bool {
    matches!(
        t,
        "ThrottlingException"
            | "TooManyRequestsException"
            | "ServiceUnavailableException"
            | "InternalServerException"
            | "InternalFailureException"
            | "InternalServerError"
    )
}

pub fn is_event_stream_content_type(ct: &str) -> bool {
    ct.split(';')
        .next()
        .map(str::trim)
        .is_some_and(|mt| mt.eq_ignore_ascii_case("application/vnd.amazon.eventstream"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // kirocc TestParseAWSExceptionType, TestNormalizeAWSExceptionType, TestIsEventStreamContentType
    #[test]
    fn parses_and_normalizes_exception_types() {
        assert_eq!(
            parse_exception_type(
                br#"{"__type":"com.amazon.coral.service#ThrottlingException","message":"x"}"#
            )
            .as_deref(),
            Some("ThrottlingException")
        );
        assert_eq!(
            parse_exception_type(br#"{"type":"InternalServerException"}"#).as_deref(),
            Some("InternalServerException")
        );
        assert_eq!(
            parse_exception_type(br#"{"code":"ValidationException"}"#).as_deref(),
            Some("ValidationException")
        );
        assert_eq!(parse_exception_type(b"not json"), None);
        assert_eq!(
            normalize_exception_type("ThrottlingException:http://example.com"),
            "ThrottlingException"
        );
        assert!(is_retryable_exception("ThrottlingException"));
        assert!(is_retryable_exception("InternalServerException"));
        assert!(!is_retryable_exception("ValidationException"));
        assert!(is_event_stream_content_type(
            "application/vnd.amazon.eventstream"
        ));
        assert!(is_event_stream_content_type(
            "Application/VND.Amazon.EventStream; charset=utf-8"
        ));
        assert!(!is_event_stream_content_type("application/json"));
    }

    #[test]
    fn only_exact_markers_refine_throttling() {
        assert_eq!(
            classify_throttle(429, br#"{"message":"x"}"#),
            UpstreamErrorKind::Throttled
        );
        assert_eq!(
            classify_throttle(429, b"INSUFFICIENT_MODEL_CAPACITY"),
            UpstreamErrorKind::ModelCapacity
        );
        assert_eq!(
            classify_throttle(500, b"INSUFFICIENT_MODEL_CAPACITY"),
            UpstreamErrorKind::ModelCapacity
        );
        assert_eq!(
            classify_throttle(429, b"quota limit"),
            UpstreamErrorKind::Throttled
        );
        assert_eq!(
            classify_throttle(500, b"quota limit"),
            UpstreamErrorKind::Server
        );
        assert_eq!(
            classify_throttle(429, b"MONTHLY_REQUEST_COUNT"),
            UpstreamErrorKind::AllowanceExhausted
        );
        assert_eq!(
            classify_throttle(500, b"MONTHLY_REQUEST_COUNT"),
            UpstreamErrorKind::AllowanceExhausted
        );
        assert_eq!(
            classify_throttle(429, b"INSUFFICIENT_MODEL_CAPACITY MONTHLY_REQUEST_COUNT"),
            UpstreamErrorKind::ModelCapacity
        );
        assert_eq!(
            classify_throttle(429, b"monthly request count"),
            UpstreamErrorKind::Throttled
        );
    }
}

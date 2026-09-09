//! Upstream error classification (spec 5.6). Transcribed from kirocc
//! internal/kiroclient/aws_error.go.

use serde_json::Value;

pub const MAX_MESSAGE_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamErrorKind {
    /// 403 after a refresh attempt, or no usable credential.
    Auth,
    /// 429, ThrottlingException, TooManyRequestsException.
    Throttled,
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
    /// Capped at 1 KiB; never carries request content.
    pub message: String,
}

impl UpstreamError {
    pub fn new(
        kind: UpstreamErrorKind,
        status: Option<u16>,
        exception_type: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        let mut message: String = message.into();
        if message.len() > MAX_MESSAGE_BYTES {
            let mut end = MAX_MESSAGE_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        UpstreamError {
            kind,
            status,
            exception_type,
            message,
        }
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
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default()
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
}

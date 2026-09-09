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
    let raw = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();
    scrub_identifiers(&raw)
}

/// Removes AWS identifiers that must never reach a client or a log
/// (`CLAUDE.md`): an ARN becomes `arn:***`, and a bare 12-digit account id
/// becomes `***`. Applied before the 1 KiB cap in [`UpstreamError::new`] so a
/// truncated ARN cannot survive.
fn scrub_identifiers(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if s[i..].starts_with("arn:") {
            let mut j = i + "arn:".len();
            while j < bytes.len() {
                let b = bytes[j];
                if b.is_ascii_whitespace() || b == b'"' || b == b'\'' {
                    break;
                }
                j += 1;
            }
            out.push_str("arn:***");
            i = j;
            continue;
        }
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - start == 12 {
                out.push_str("***");
            } else {
                out.push_str(&s[start..j]);
            }
            i = j;
            continue;
        }
        let ch = s[i..]
            .chars()
            .next()
            .expect("i < bytes.len() is a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
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
    fn scrub_identifiers_masks_arns_with_no_surviving_digits() {
        assert_eq!(
            scrub_identifiers(
                "denied for arn:aws:codewhisperer:us-east-1:123456789012:profile/AAA"
            ),
            "denied for arn:***"
        );
    }

    #[test]
    fn scrub_identifiers_masks_a_bare_twelve_digit_account_id() {
        assert_eq!(
            scrub_identifiers("account 123456789012 rejected"),
            "account *** rejected"
        );
    }

    #[test]
    fn scrub_identifiers_leaves_a_thirteen_digit_run_untouched() {
        assert_eq!(
            scrub_identifiers("stamp 1234567890123"),
            "stamp 1234567890123"
        );
    }

    #[test]
    fn scrub_identifiers_leaves_an_eleven_digit_run_untouched() {
        assert_eq!(scrub_identifiers("short 12345678901"), "short 12345678901");
    }
}

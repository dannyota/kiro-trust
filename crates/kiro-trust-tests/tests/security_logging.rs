//! spec 6.4 and 8.4: run real flows at debug level and scan every log line.

mod common {
    include!("server.rs");
}

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{TOKEN, app, body_string, test_db};
use futures_util::StreamExt;
use kiro_trust::server::{AppState, build_router};
use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::{KiroClient, Upstream, UpstreamError, UpstreamErrorKind, UpstreamStream};
use kiro_trust_net::{Client, Policy};
use kiro_trust_protocol::eventstream::encode_event_frame;
use kiro_trust_protocol::kiro::Payload;
use secrecy::SecretString;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tower::ServiceExt;

struct FixedAttemptUpstream {
    responses: Mutex<Vec<Result<Vec<u8>, UpstreamError>>>,
}

#[async_trait::async_trait]
impl Upstream for FixedAttemptUpstream {
    async fn generate(&self, _payload: &Payload) -> Result<UpstreamStream, UpstreamError> {
        let bytes = self.responses.lock().unwrap().remove(0)?;
        let chunks = bytes
            .chunks(7)
            .map(|chunk| Ok::<bytes::Bytes, UpstreamError>(bytes::Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>();
        Ok(UpstreamStream {
            attempts: 13,
            bytes: futures_util::stream::iter(chunks).boxed(),
        })
    }
}

fn counted_app(
    dir: &std::path::Path,
    responses: Vec<Result<Vec<u8>, UpstreamError>>,
) -> axum::Router {
    let net = Arc::new(Client::new(Policy::loopback_plain_http(1)).unwrap());
    let state = Arc::new(AppState {
        tokens: Arc::new(TokenSource::new(test_db(dir), net, None)),
        upstream: Arc::new(FixedAttemptUpstream {
            responses: Mutex::new(responses),
        }),
        local_token: SecretString::from(TOKEN.to_string()),
        limiter: Arc::new(tokio::sync::Semaphore::new(32)),
        conversation_salt: [3; 16],
    });
    build_router(state)
}

fn messages_request(stream: bool) -> Request<Body> {
    Request::post("/v1/messages")
        .header("x-api-key", TOKEN)
        .body(Body::from(
            serde_json::json!({
                "model": "claude-sonnet-4-6", "max_tokens": 10, "stream": stream,
                "messages": [{"role": "user", "content": "hi"}]
            })
            .to_string(),
        ))
        .unwrap()
}

fn event_frames(events: &[(&str, &str)]) -> Vec<u8> {
    events
        .iter()
        .flat_map(|(kind, json)| encode_event_frame(kind, json.as_bytes()))
        .collect()
}

/// spec 6.4's allowed-fields list, transcribed here so a field reaching a
/// log line without a matching spec update fails `nothing_sensitive_reaches_the_logs`
/// below. Keep this in sync with `docs/specs/kiro-trust-design.md` section
/// 6.4 by hand: a field added to one without the other is exactly the drift
/// this list exists to catch.
const ALLOWED_LOG_FIELDS: &[&str] = &[
    "request_id",
    "method",
    "path",
    "model",
    "kiro_model",
    "stream",
    "status",
    "duration_ms",
    "retry_count",
    "attempt",
    "input_bytes",
    "output_bytes",
    "input_tokens",
    "output_tokens",
    "runtime_region",
    "sso_region",
    "frames",
    "event_counts",
    "error_type",
];

/// Every `name=` token in `line` that is not inside a quoted field value.
/// `tracing_subscriber`'s default formatter writes `key=value` pairs
/// space-separated after the level, target, and message, with string values
/// quoted; scanning outside quotes keeps a value that happens to contain an
/// `=` or a space from being mistaken for another field.
fn field_names(line: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut ident_start: Option<usize> = None;
    for (i, c) in line.char_indices() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_quotes = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_quotes = true;
                ident_start = None;
            }
            'a'..='z' | 'A'..='Z' | '_' => {
                if ident_start.is_none() {
                    ident_start = Some(i);
                }
            }
            '0'..='9' => {} // valid mid-identifier; tracing field names never start with one
            '=' => {
                if let Some(start) = ident_start {
                    names.push(&line[start..i]);
                }
                ident_start = None;
            }
            _ => ident_start = None,
        }
    }
    names
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

static LOG: OnceLock<Capture> = OnceLock::new();

/// Install the capturing subscriber as the process-wide default, once, and
/// return its buffer.
///
/// This binary also runs `server.rs`'s own `#[tokio::test]`s (included
/// above as `common::`), each on its own OS thread with no subscriber of
/// its own. tracing caches each call site's `Interest` globally the first
/// time any thread hits it; a thread-local override
/// (`tracing::subscriber::set_default`) is only visible on the thread that
/// installed it, so whichever `common::` test's thread reaches a given
/// `tracing::info!`/`warn!` call site first "wins" and permanently caches
/// "never interested" there, because that thread has no subscriber at all
/// (see `tracing::callsite`'s docs on rebuilding cached interest). A
/// process-wide default is the fallback on every thread with no override,
/// so it decides interest correctly no matter which test or thread gets
/// there first, and it also corrects any call site whose interest was
/// already cached "never" before this runs.
fn capture() -> Capture {
    LOG.get_or_init(|| {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(kiro_trust::logging::filter("debug"))
            .with_writer(capture.clone())
            .finish();
        // A silently discarded error here would leave the capture inert
        // (an empty buffer) with no indication why every marker assertion
        // below is vacuously true.
        tracing::subscriber::set_global_default(subscriber)
            .expect("capture subscriber installed once");
        capture
    })
    .clone()
}

#[tokio::test]
async fn successful_invalid_state_replay_logs_total_completed_retries() {
    let capture = capture();
    let start = capture.0.lock().unwrap().len();
    let dir = tempfile::tempdir().unwrap();
    let app = counted_app(
        dir.path(),
        vec![
            Ok(event_frames(&[(
                "invalidStateEvent",
                r#"{"reason":"STALE_CONVERSATION","message":"stale"}"#,
            )])),
            Ok(event_frames(&[(
                "assistantResponseEvent",
                r#"{"content":"ok"}"#,
            )])),
        ],
    );
    let response = app.oneshot(messages_request(true)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = body_string(response).await;
    let logs = String::from_utf8(capture.0.lock().unwrap()[start..].to_vec()).unwrap();
    assert!(
        logs.lines()
            .any(|line| line.contains("response") && line.contains("retry_count=25")),
        "successful replay must log both calls' completed attempts: {logs}"
    );
}

#[tokio::test]
async fn failed_invalid_state_replay_logs_total_completed_retries() {
    let capture = capture();
    let start = capture.0.lock().unwrap().len();
    let dir = tempfile::tempdir().unwrap();
    let app = counted_app(
        dir.path(),
        vec![
            Ok(event_frames(&[(
                "invalidStateEvent",
                r#"{"reason":"STALE_CONVERSATION","message":"first"}"#,
            )])),
            Err(UpstreamError::new(
                UpstreamErrorKind::Server,
                Some(503),
                None,
                17,
                None,
                "synthetic terminal error",
            )),
        ],
    );
    let response = app.oneshot(messages_request(false)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let _ = body_string(response).await;
    let logs = String::from_utf8(capture.0.lock().unwrap()[start..].to_vec()).unwrap();
    assert!(
        logs.lines()
            .any(|line| line.contains("request failed") && line.contains("retry_count=29")),
        "failed replay must log the stream and terminal error attempts: {logs}"
    );
}

#[tokio::test]
async fn decoded_capacity_retry_does_not_log_a_hostile_exception_type() {
    const HOSTILE_TYPE: &str = "HOSTILE_EXCEPTION_TYPE";

    let capture = capture();
    let start = capture.0.lock().unwrap().len();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(
        Client::new(Policy::loopback_plain_http(
            listener.local_addr().unwrap().port(),
        ))
        .unwrap(),
    );
    let tokens = Arc::new(TokenSource::new(test_db(dir.path()), net.clone(), None));
    let state = Arc::new(AppState {
        tokens: tokens.clone(),
        upstream: Arc::new(
            KiroClient::new(net, tokens, false).with_base_delay(Duration::from_millis(1)),
        ),
        local_token: SecretString::from(TOKEN.to_string()),
        limiter: Arc::new(tokio::sync::Semaphore::new(32)),
        conversation_salt: [5; 16],
    });
    let body = format!(r#"{{"__type":"{HOSTILE_TYPE}","message":"INSUFFICIENT_MODEL_CAPACITY"}}"#);
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let request = tokio::spawn(build_router(state).oneshot(messages_request(false)));
    for _ in 0..3 {
        let (mut connection, _) = listener.accept().await.unwrap();
        connection.write_all(response.as_bytes()).await.unwrap();
    }
    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let logs = String::from_utf8(capture.0.lock().unwrap()[start..].to_vec()).unwrap();
    assert!(
        !logs.contains(HOSTILE_TYPE),
        "a decoded exception type must not reach the retry logs: {logs}"
    );
    assert!(
        logs.lines().any(|line| {
            line.contains("200 with an exception body, retrying")
                && line.contains("error_type=\"model_capacity\"")
        }),
        "model-capacity retries must use the fixed error type: {logs}"
    );
}

#[tokio::test]
async fn nothing_sensitive_reaches_the_logs() {
    let capture = capture();

    let dir = tempfile::tempdir().unwrap();
    // Well-formed tool_use/tool_result pair (Important 3): a bare orphan
    // tool_result would be textualized by `normalize_messages` before it
    // ever reaches history (see `translate/normalize.rs`'s
    // `textualize_orphan_tool_results`), changing the message shape instead
    // of exercising the tool-result path. Pairing the id with a `tool_use`
    // in the immediately preceding assistant message keeps it a real block
    // (see `translate/history.rs`'s `extract_tool_results`).
    let frames: Vec<u8> = [
        encode_event_frame(
            "reasoningContentEvent",
            br#"{"text":"THINKING_MARKER_c4f","signature":"s"}"#,
        ),
        encode_event_frame("assistantResponseEvent", br#"{"content":"RESPONSE_MARKER_9f1"}"#),
        encode_event_frame(
            "toolUseEvent",
            br#"{"toolUseId":"toolu_MARKER","name":"mcp__secretserver__tool","input":"{\"cmd\":\"ARG_MARKER_7c2\"}","stop":true}"#,
        ),
        encode_event_frame(
            "messageMetadataEvent",
            br#"{"conversationId":"CONV_MARKER","utteranceId":"u"}"#,
        ),
    ]
    .concat();
    let (app, _) = app(
        dir.path(),
        vec![Ok(frames.clone()), Ok(frames.clone()), Ok(frames)],
    );
    // The real home directory is a marker too: it must never appear in a log line.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/nonexistent-home".to_string());
    for stream in [true, false] {
        let req = serde_json::json!({
            "model": "claude-sonnet-4-6", "max_tokens": 50, "stream": stream,
            "thinking": {"type": "enabled"},
            "system": format!("SYSTEM_MARKER_3a4 {home}/private"),
            "tools": [{"name": "mcp__secretserver__tool", "description": "TOOL_DESC_MARKER", "input_schema": {"type": "object"}}],
            "messages": [
                {"role": "user", "content": "PROMPT_MARKER_5b6 with a fake key sk-ant-MARKER"},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "toolu_pair1", "name": "mcp__secretserver__tool", "input": {"path": "x"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_pair1", "content": "TOOL_RESULT_MARKER_8d3"}
                ]}
            ]
        });
        let r = app
            .clone()
            .oneshot(
                Request::post("/v1/messages")
                    .header("x-api-key", TOKEN)
                    .header("x-claude-code-session-id", "SESSION_MARKER")
                    .body(Body::from(req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // A 200 proves this request reached the code that could log it,
        // rather than failing earlier for an unrelated reason.
        assert_eq!(r.status(), StatusCode::OK, "stream={stream}");
        let body = body_string(r).await;
        if !stream {
            // Proves the response marker actually traversed translation and
            // the response-logging call site, not just the request side.
            assert!(
                body.contains("RESPONSE_MARKER_9f1"),
                "non-streaming response body missing the response marker: {body}"
            );
        }
    }
    // Image markers (Task 2, v0.2.0): one accepted image (spec 5.3) and
    // one request per rejected class (spec 5.5), so an accepted OR a
    // rejected image leaking into a log line is caught either way. The
    // data marker is a run of base64-alphabet characters embedded directly
    // in the `data` field: `IMGDATAMARKERb7e` followed by padding zero
    // bytes is itself valid base64 (no separate encoding step needed), so
    // it appears verbatim in the request whether the image is accepted or
    // rejected.
    const IMAGE_DATA_MARKER: &str = "IMGDATAMARKERb7e";
    let image_data = format!("{IMAGE_DATA_MARKER}{}", "AAAA".repeat(3));
    const MEDIA_TYPE_MARKER: &str = "image/MEDIATYPEMARKERe2a";
    // A count over the limit. The leak-sweep below checks for
    // "images: {COUNT_MARKER_IMAGES}" (the `ImageError::TooMany` message's
    // own shape) rather than the bare digits: this binary's other tests
    // share one process-wide log-capture buffer (see `capture()` above)
    // and run concurrently, so a short, undecorated number like "11" would
    // incidentally match unrelated log content (byte counts, timestamps,
    // frame counts) from those tests and make this assertion flaky. The
    // longer, message-shaped substring keeps the same intent, since spec
    // 6.4's allowlist has no field for this count and nothing should log
    // it, while no longer colliding with ordinary log output.
    const COUNT_MARKER_IMAGES: usize =
        kiro_trust_protocol::translate::content::MAX_IMAGES_PER_REQUEST + 1;

    let accepted_image_req = serde_json::json!({
        "model": "claude-sonnet-4-6", "max_tokens": 50, "stream": false,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "look"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image_data}}
        ]}]
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from(accepted_image_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "accepted image request");
    let _ = body_string(r).await;

    // Rejected: unsupported media type, naming the marker in the 400 body
    // (never in a log).
    let rejected_media_type_req = serde_json::json!({
        "model": "claude-sonnet-4-6", "max_tokens": 50,
        "messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": MEDIA_TYPE_MARKER, "data": "AAAA"}}
        ]}]
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from(rejected_media_type_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "unsupported media type"
    );
    let _ = body_string(r).await;

    // Rejected: invalid base64, still carrying the data marker (mangled,
    // but the marker text itself survives as a substring).
    let rejected_base64_req = serde_json::json!({
        "model": "claude-sonnet-4-6", "max_tokens": 50,
        "messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": format!("{IMAGE_DATA_MARKER}!!!not-valid")}}
        ]}]
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from(rejected_base64_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "invalid base64");
    let _ = body_string(r).await;

    // Rejected: over the per-request image count.
    let content: Vec<_> = (0..COUNT_MARKER_IMAGES)
        .map(|_| serde_json::json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}))
        .collect();
    let rejected_count_req = serde_json::json!({
        "model": "claude-sonnet-4-6", "max_tokens": 50,
        "messages": [{"role": "user", "content": content}]
    });
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from(rejected_count_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "too many images");
    let _ = body_string(r).await;

    // An auth failure (fails in require_token, before any body parsing).
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("authorization", "Bearer WRONG_TOKEN_MARKER")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let _ = body_string(r).await;
    // An authenticated but malformed body, so the 400 `invalid_request`
    // path (a plausible leak site for a parse error) is genuinely exercised
    // too, not just the auth-failure path above. The body carries a marker
    // inside otherwise-malformed JSON (the closing brace is missing) so a
    // parse error that ever echoed body content into the logs would be
    // caught by the marker sweep below; a body with no marker at all could
    // not detect that.
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from("{\"model\":\"PROMPT_MARKER_5b6\""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let _ = body_string(r).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // Important 2: `logs.contains("request")` used to pass on any of the 22
    // `common::` tests' output sharing this process-wide buffer (the
    // `request_id` field name and the literal "request failed" message both
    // contain "request"), so it proved nothing about whether *this* test's
    // own flows reached a log line. A line carrying both `path` set to
    // `/v1/messages` and `input_bytes` only ever comes from the one log
    // call site this test depends on (`messages.rs`'s initial per-request
    // "request" log), so this still catches the failure mode the guard
    // exists for: if a catalog rename, a token change, a route change, or a
    // middleware change ever stopped *any* `/v1/messages` request in this
    // binary from reaching that call site, this line would stop appearing
    // and the assertion would fail.
    assert!(
        logs.lines()
            .any(|l| l.contains("path=\"/v1/messages\"") && l.contains("input_bytes=")),
        "logging is active: no /v1/messages request line with input_bytes seen:\n{logs}"
    );
    for marker in [
        "RESPONSE_MARKER",
        "ARG_MARKER",
        "SYSTEM_MARKER",
        "PROMPT_MARKER",
        "TOOL_DESC_MARKER",
        "sk-ant-MARKER",
        "mcp__secretserver",
        "toolu_MARKER",
        "CONV_MARKER",
        "SESSION_MARKER",
        "WRONG_TOKEN_MARKER",
        TOKEN,
        "Bearer",
        "tok\"",
        home.as_str(),
        "000000000000",
        "arn:aws",
        "TOOL_RESULT_MARKER",
        "THINKING_MARKER",
        dir.path().to_str().unwrap(),
        IMAGE_DATA_MARKER,
        MEDIA_TYPE_MARKER,
        &format!("images: {COUNT_MARKER_IMAGES}"),
    ] {
        assert!(!logs.contains(marker), "{marker} leaked into logs:\n{logs}");
    }

    // Important 1: spec 6.4's allowlist is only as good as something that
    // fails when a field name drifts from it. This does not prove every
    // allowed field is exercised, only that nothing beyond the allowlist
    // ever appears on a line this test's flows produced; a new field
    // reaching a `tracing::info!`/`warn!` call site without a matching spec
    // update fails here.
    for line in logs.lines() {
        for name in field_names(line) {
            assert!(
                ALLOWED_LOG_FIELDS.contains(&name),
                "field `{name}` is outside spec 6.4's allowlist:\n{line}"
            );
        }
    }
}

//! spec 6.4 and 8.4: run real flows at debug level and scan every log line.

mod common {
    include!("server.rs");
}

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{TOKEN, app, body_string};
use kiro_trust_protocol::eventstream::encode_event_frame;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use tower::ServiceExt;

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
    let (app, _) = app(dir.path(), vec![Ok(frames.clone()), Ok(frames)]);
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
    ] {
        assert!(!logs.contains(marker), "{marker} leaked into logs:\n{logs}");
    }
}

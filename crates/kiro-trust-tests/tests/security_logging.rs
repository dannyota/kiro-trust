//! spec 6.4 and 8.4: run real flows at debug level and scan every log line.

mod common {
    include!("server.rs");
}

use axum::body::Body;
use axum::http::Request;
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
        let _ = tracing::subscriber::set_global_default(subscriber);
        capture
    })
    .clone()
}

#[tokio::test]
async fn nothing_sensitive_reaches_the_logs() {
    let capture = capture();

    let dir = tempfile::tempdir().unwrap();
    let frames: Vec<u8> = [
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
            "system": format!("SYSTEM_MARKER_3a4 {home}/private"),
            "tools": [{"name": "mcp__secretserver__tool", "description": "TOOL_DESC_MARKER", "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "PROMPT_MARKER_5b6 with a fake key sk-ant-MARKER"}]
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
        let _ = body_string(r).await;
    }
    // Force an auth failure and a bad request too.
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
    let _ = body_string(r).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("request"), "logging is active: {logs}");
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
    ] {
        assert!(!logs.contains(marker), "{marker} leaked into logs:\n{logs}");
    }
}

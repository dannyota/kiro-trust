use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use kiro_trust::server::{AppState, build_router};
use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::{Upstream, UpstreamError, UpstreamStream};
use kiro_trust_net::{Client, Policy};
use kiro_trust_protocol::kiro::Payload;
use rusqlite::Connection;
use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

pub const TOKEN: &str = "test-local-token";

/// Scripted upstream: pops one response per call, records payloads.
pub struct Scripted {
    pub responses: Mutex<Vec<Result<Vec<u8>, UpstreamError>>>,
    pub payloads: Mutex<Vec<serde_json::Value>>,
    /// Raw byte chunk size the response is delivered in. 7 (the historical
    /// default, kept so no existing test changes behavior) crosses frame
    /// seams across chunk boundaries; a large value (`usize::MAX`) delivers
    /// a whole response in one chunk, needed to reproduce a failure sharing
    /// a chunk with real output.
    pub chunk_size: usize,
}

#[async_trait::async_trait]
impl Upstream for Scripted {
    async fn generate(&self, payload: &Payload) -> Result<UpstreamStream, UpstreamError> {
        self.payloads
            .lock()
            .unwrap()
            .push(serde_json::to_value(payload).unwrap());
        let next = self.responses.lock().unwrap().remove(0);
        let bytes = next?;
        let chunks: Vec<Result<bytes::Bytes, UpstreamError>> = bytes
            .chunks(self.chunk_size.max(1))
            .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
            .collect();
        Ok(UpstreamStream {
            attempts: 1,
            bytes: futures_util::stream::iter(chunks).boxed(),
        })
    }
}

pub fn test_db(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("data.sqlite3");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT); CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB);").unwrap();
    c.execute("INSERT INTO auth_kv VALUES ('kirocli:odic:token', '{\"access_token\":\"tok\",\"refresh_token\":\"r\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"region\":\"ap-southeast-1\"}')", []).unwrap();
    c.execute("INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{\"clientId\":\"c\",\"clientSecret\":\"s\"}')", []).unwrap();
    c.execute("INSERT INTO state VALUES ('api.codewhisperer.profile', '{\"arn\":\"arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE\"}')", []).unwrap();
    p
}

pub fn app(
    dir: &std::path::Path,
    responses: Vec<Result<Vec<u8>, UpstreamError>>,
) -> (axum::Router, Arc<Scripted>) {
    app_with_chunk_size(dir, responses, 7)
}

pub fn app_with_chunk_size(
    dir: &std::path::Path,
    responses: Vec<Result<Vec<u8>, UpstreamError>>,
    chunk_size: usize,
) -> (axum::Router, Arc<Scripted>) {
    let net = Arc::new(Client::new(Policy::loopback_plain_http(1)).unwrap());
    let tokens = Arc::new(TokenSource::new(test_db(dir), net, None));
    let scripted = Arc::new(Scripted {
        responses: Mutex::new(responses),
        payloads: Mutex::new(vec![]),
        chunk_size,
    });
    let state = Arc::new(AppState {
        tokens,
        upstream: scripted.clone(),
        local_token: SecretString::from(TOKEN.to_string()),
        limiter: Arc::new(tokio::sync::Semaphore::new(32)),
        conversation_salt: [7u8; 16],
    });
    (build_router(state), scripted)
}

pub async fn body_string(resp: axum::response::Response) -> String {
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn health_needs_no_token_but_everything_else_does() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(dir.path(), vec![]);
    let r = app
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body_string(r).await, "{\"status\":\"ok\"}");

    let r = app
        .clone()
        .oneshot(Request::get("/v1/models").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(r.headers().get("www-authenticate").is_none());
    assert_eq!(
        body_string(r).await,
        "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"missing or invalid local token\"}}"
    );

    let r = app
        .clone()
        .oneshot(
            Request::get("/v1/models")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    for (name, value) in [
        ("authorization", format!("Bearer {TOKEN}")),
        ("x-api-key", TOKEN.to_string()),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::get("/v1/models")
                    .header(name, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{name}");
        let body: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
        assert_eq!(body["object"], "list");
        assert!(
            body["data"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["id"] == "claude-sonnet-4-6[1m]"
                    && m["display_name"] == "Sonnet 4.6 (1M context)")
        );
        assert!(
            body["data"]
                .as_array()
                .unwrap()
                .iter()
                .all(|m| m["owned_by"] == "kiro" && m["object"] == "model")
        );
    }
}

#[tokio::test]
async fn unknown_routes_and_methods_use_the_error_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(dir.path(), vec![]);
    let r = app
        .clone()
        .oneshot(
            Request::get("/v1/other")
                .header("x-api-key", TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(body_string(r).await.contains("\"not_found_error\""));
    let r = app
        .clone()
        .oneshot(
            Request::options("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        r.headers().get("access-control-allow-origin").is_none(),
        "no CORS headers"
    );

    // The unmatched-path and unmatched-method fallbacks sit behind the token
    // check too: with no token at all, both return 401, not 404 or 405.
    const UNAUTHENTICATED: &str = "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"missing or invalid local token\"}}";
    let r = app
        .clone()
        .oneshot(Request::get("/v1/other").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_string(r).await, UNAUTHENTICATED);

    let r = app
        .clone()
        .oneshot(
            Request::options("/v1/messages")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_string(r).await, UNAUTHENTICATED);
}

#[tokio::test]
async fn an_empty_token_never_authenticates_even_against_an_empty_local_token() {
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(1)).unwrap());
    let tokens = Arc::new(TokenSource::new(test_db(dir.path()), net, None));
    let upstream = Arc::new(Scripted {
        responses: Mutex::new(vec![]),
        payloads: Mutex::new(vec![]),
        chunk_size: 7,
    });
    let state = Arc::new(AppState {
        tokens,
        upstream,
        local_token: SecretString::from(String::new()),
        limiter: Arc::new(tokio::sync::Semaphore::new(32)),
        conversation_salt: [7u8; 16],
    });
    let app = build_router(state);

    // Bearer with empty value (trailing space).
    let r = app
        .clone()
        .oneshot(
            Request::get("/v1/models")
                .header("authorization", "Bearer ")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // x-api-key with empty value.
    let r = app
        .clone()
        .oneshot(
            Request::get("/v1/models")
                .header("x-api-key", "")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // No auth header at all.
    let r = app
        .clone()
        .oneshot(Request::get("/v1/models").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

use kiro_trust_protocol::eventstream::{encode_event_frame, encode_exception_frame};

fn frames(events: &[(&str, &str)]) -> Vec<u8> {
    events
        .iter()
        .flat_map(|(t, p)| encode_event_frame(t, p.as_bytes()))
        .collect()
}
fn messages_req(body: serde_json::Value) -> Request<Body> {
    Request::post("/v1/messages")
        .header("x-api-key", TOKEN)
        .header("content-type", "application/json")
        .header("x-claude-code-session-id", "session-abc")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn streams_sse_with_the_fixture_shape() {
    let dir = tempfile::tempdir().unwrap();
    let (app, scripted) = app(
        dir.path(),
        vec![Ok(frames(&[
            ("assistantResponseEvent", r#"{"content":"Hel"}"#),
            ("assistantResponseEvent", r#"{"content":"lo"}"#),
            (
                "metadataEvent",
                r#"{"tokenUsage":{"uncachedInputTokens":5,"outputTokens":1,"totalTokens":6,"cacheReadInputTokens":0,"cacheWriteInputTokens":0}}"#,
            ),
        ]))],
    );
    let r = app
        .oneshot(messages_req(serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]})))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-type"], "text/event-stream");
    let body = body_string(r).await;
    assert!(body.starts_with("event: message_start\ndata: {\"type\":\"message_start\""));
    assert!(body.contains("\"text\":\"Hel\""));
    assert!(body.contains("\"text\":\"lo\""));
    assert!(body.contains("\"stop_reason\":\"end_turn\""));
    assert!(body.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"));
    let payload = &scripted.payloads.lock().unwrap()[0];
    assert_eq!(
        payload["conversationState"]["currentMessage"]["userInputMessage"]["modelId"],
        "claude-sonnet-4.6"
    );
    assert_eq!(
        payload["profileArn"],
        "arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE"
    );
    let conv = payload["conversationState"]["conversationId"]
        .as_str()
        .unwrap();
    assert!(
        !conv.contains("session-abc"),
        "the raw session id never reaches Kiro"
    );
    assert_eq!(conv.len(), 36);
}

#[tokio::test]
async fn conversation_id_is_stable_per_session_and_random_without_a_header() {
    let dir = tempfile::tempdir().unwrap();
    let body = frames(&[("assistantResponseEvent", r#"{"content":"x"}"#)]);
    let (app, scripted) = app(
        dir.path(),
        vec![Ok(body.clone()), Ok(body.clone()), Ok(body.clone())],
    );
    let req = || serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]});
    app.clone().oneshot(messages_req(req())).await.unwrap();
    app.clone().oneshot(messages_req(req())).await.unwrap();
    app.clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from(req().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let p = scripted.payloads.lock().unwrap();
    assert_eq!(
        p[0]["conversationState"]["conversationId"],
        p[1]["conversationState"]["conversationId"]
    );
    assert_ne!(
        p[0]["conversationState"]["conversationId"],
        p[2]["conversationState"]["conversationId"]
    );
}

#[tokio::test]
async fn non_streaming_returns_a_folded_message() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(
        dir.path(),
        vec![Ok(frames(&[
            ("reasoningContentEvent", r#"{"text":"t","signature":"s"}"#),
            ("assistantResponseEvent", r#"{"content":"42"}"#),
            (
                "toolUseEvent",
                r#"{"toolUseId":"t1","name":"Read","input":"{\"p\":1}","stop":true}"#,
            ),
        ]))],
    );
    let r = app
        .oneshot(messages_req(serde_json::json!({"model": "claude-opus-4-6", "max_tokens": 10, "stream": false, "thinking": {"type": "enabled"}, "messages": [{"role": "user", "content": "hi"}]})))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    assert_eq!(v["type"], "message");
    assert_eq!(v["model"], "claude-opus-4-6[1m]");
    assert_eq!(v["content"][0]["type"], "thinking");
    assert_eq!(v["content"][1]["text"], "42");
    assert_eq!(v["content"][2]["name"], "Read");
    assert_eq!(v["stop_reason"], "tool_use");
}

#[tokio::test]
async fn request_validation_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(dir.path(), vec![]);
    let r = app
        .clone()
        .oneshot(messages_req(
            serde_json::json!({"model": "gpt-5.6-sol", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_string(r)
            .await
            .contains("gpt-5.6-sol is not in the kiro-trust catalog")
    );
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = app
        .clone()
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": []}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(body_string(r).await.contains("messages must not be empty"));
}

// Critical fix: `max_tokens` is `#[serde(default)]` on `anthropic::Request`
// because `count_tokens` shares `parse_request` and legitimately omits the
// field (spec 5.7); the requirement itself lives only in `post_messages`
// (spec 5.1). This pins both halves: `/v1/messages` rejects an absent
// `max_tokens`, and `count_tokens` is unaffected.
#[tokio::test]
async fn v1_messages_requires_max_tokens_but_count_tokens_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let (app, scripted) = app(dir.path(), vec![]);
    let r = app
        .clone()
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let body = body_string(r).await;
    assert!(body.contains("\"invalid_request_error\""));
    assert!(body.contains("max_tokens"));
    assert!(
        scripted.payloads.lock().unwrap().is_empty(),
        "rejected before any upstream call"
    );

    // An explicit 0 is rejected the same way as an absent field: the real
    // Anthropic API also treats `max_tokens: 0` as invalid.
    let r = app
        .clone()
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 0, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let r = app
        .oneshot(
            Request::post("/v1/messages/count_tokens")
                .header("x-api-key", TOKEN)
                .body(Body::from(
                    serde_json::json!({"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "hi"}]})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "count_tokens legitimately omits max_tokens (spec 5.7)"
    );
}

#[tokio::test]
async fn oversized_body_returns_the_error_envelope_not_axums_default_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(dir.path(), vec![]);
    let big = vec![b'a'; kiro_trust::server::MAX_BODY_BYTES + 1];
    let r = app
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", TOKEN)
                .body(Body::from(big))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "spec 5.6: 413 request_too_large, not axum's default rejection"
    );
    assert_eq!(r.headers()["content-type"], "application/json");
    let body = body_string(r).await;
    assert!(body.contains("\"request_too_large\""));
    assert!(
        !body.to_lowercase().contains("failed to buffer"),
        "not axum's default text"
    );
}

#[tokio::test]
async fn upstream_errors_map_to_the_envelope() {
    // Each scenario is scoped in its own block: `let (app, _) = app(...)`
    // shadows the `app()` helper function for the rest of the enclosing
    // scope, so a bare sequence of `let (app, _) = app(...)` statements
    // would make the second call try to invoke the `Router` value from the
    // first as a function.
    {
        let dir = tempfile::tempdir().unwrap();
        let throttled = UpstreamError::new(
            kiro_trust_kiro::UpstreamErrorKind::Throttled,
            Some(429),
            Some("ThrottlingException".into()),
            1,
            None,
            "slow down",
        );
        let (app, _) = app(dir.path(), vec![Err(throttled)]);
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(body_string(r).await.contains("\"rate_limit_error\""));
    }

    {
        let dir = tempfile::tempdir().unwrap();
        let throttled = UpstreamError::new(
            kiro_trust_kiro::UpstreamErrorKind::Throttled,
            Some(429),
            Some("ThrottlingException".into()),
            3,
            Some(std::time::Duration::from_millis(60_001)),
            "slow down",
        );
        let (app, _) = app(dir.path(), vec![Err(throttled)]);
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers().get("retry-after").unwrap(), "61");
    }

    {
        let dir = tempfile::tempdir().unwrap();
        let unavailable = UpstreamError::new(
            kiro_trust_kiro::UpstreamErrorKind::Server,
            Some(503),
            Some("ServiceUnavailableException".into()),
            1,
            Some(std::time::Duration::from_secs(61)),
            "busy",
        );
        let (app, _) = app(dir.path(), vec![Err(unavailable)]);
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(r.headers().get("retry-after").unwrap(), "61");
    }

    // An exception frame before any output is an HTTP error; a throttling
    // exception maps to 429.
    {
        let dir = tempfile::tempdir().unwrap();
        let (app, _) = app(
            dir.path(),
            vec![Ok(encode_exception_frame(
                "ThrottlingException",
                br#"{"message":"busy"}"#,
            ))],
        );
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // After output started, the failure is an SSE error event.
    {
        let dir = tempfile::tempdir().unwrap();
        let mut body = frames(&[("assistantResponseEvent", r#"{"content":"part"}"#)]);
        body.extend(encode_exception_frame(
            "InternalServerException",
            br#"{"message":"boom"}"#,
        ));
        let (app, _) = app(dir.path(), vec![Ok(body)]);
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let text = body_string(r).await;
        assert!(text.contains("\"text\":\"part\""));
        assert!(text.ends_with(
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"InternalServerException: boom\"}}\n\n"
        ));
    }

    // A capacity marker in an exception frame has the same category as the
    // HTTP error body. Once text has reached the client, the stream does not
    // replay; it terminates with the normalized SSE error.
    {
        let dir = tempfile::tempdir().unwrap();
        let mut body = frames(&[("assistantResponseEvent", r#"{"content":"part"}"#)]);
        body.extend(encode_exception_frame(
            "InternalServerException",
            br#"{"message":"INSUFFICIENT_MODEL_CAPACITY"}"#,
        ));
        let (app, _) = app(dir.path(), vec![Ok(body)]);
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let text = body_string(r).await;
        assert!(text.contains("model capacity unavailable"));
        assert!(text.contains("event: error"));
    }
}

// Critical 1: an upstream exception message can carry the caller's profile
// ARN and account id (a real AWS `AccessDeniedException` routinely echoes
// them); both must be scrubbed before the message reaches a client, on
// every path that can deliver one.
#[tokio::test]
async fn exception_message_arn_is_scrubbed_in_the_http_error_body() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(
        dir.path(),
        vec![Ok(encode_exception_frame(
            "AccessDeniedException",
            br#"{"message":"User: arn:aws:codewhisperer:us-east-1:123456789012:profile/EXAMPLE is not authorized"}"#,
        ))],
    );
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    let body = body_string(r).await;
    assert!(body.contains("arn:***"), "{body}");
    assert!(!body.contains("123456789012"), "{body}");
    assert!(!body.contains("EXAMPLE"), "{body}");
}

#[tokio::test]
async fn exception_message_arn_is_scrubbed_in_the_sse_error_event() {
    let dir = tempfile::tempdir().unwrap();
    let mut body = frames(&[("assistantResponseEvent", r#"{"content":"hi there"}"#)]);
    body.extend(encode_exception_frame(
        "AccessDeniedException",
        br#"{"message":"User: arn:aws:codewhisperer:us-east-1:123456789012:profile/EXAMPLE is not authorized"}"#,
    ));
    let (app, _) = app(dir.path(), vec![Ok(body)]);
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let text = body_string(r).await;
    assert!(text.contains("\"text\":\"hi there\""));
    assert!(text.contains("event: error"));
    assert!(text.contains("arn:***"), "{text}");
    assert!(!text.contains("123456789012"), "{text}");
}

#[tokio::test]
async fn exception_message_is_capped_at_one_kib() {
    let dir = tempfile::tempdir().unwrap();
    let long = "x".repeat(4096);
    let (app, _) = app(
        dir.path(),
        vec![Ok(encode_exception_frame(
            "InternalServerException",
            serde_json::json!({"message": long}).to_string().as_bytes(),
        ))],
    );
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    let v: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.len() <= 1024, "message was {} bytes", message.len());
}

#[tokio::test]
async fn exception_message_caps_on_a_char_boundary_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let exception_type = "InternalServerException";
    // `failure_to_error` formats "{type}: {message}" before the cap applies
    // (spec 5.6), so the multi-byte run is placed to straddle byte offset
    // 1024 of that combined string, not of `message` alone.
    let prefix_len = exception_type.len() + ": ".len();
    let n = 1023usize.saturating_sub(prefix_len);
    let message = format!("{}{}", "a".repeat(n), "é".repeat(50));
    let (app, _) = app(
        dir.path(),
        vec![Ok(encode_exception_frame(
            exception_type,
            serde_json::json!({"message": message})
                .to_string()
                .as_bytes(),
        ))],
    );
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    // `body_string` itself panics on invalid UTF-8 via `String::from_utf8`;
    // reaching the asserts below already proves that did not happen.
    let body = body_string(r).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let got = v["error"]["message"].as_str().unwrap();
    assert!(got.len() <= 1024, "message was {} bytes", got.len());
    assert!(
        !got.contains('é'),
        "the multi-byte char must be cut whole, not sliced: {got:?}"
    );
}

// Critical 2: a single upstream chunk can carry a text frame followed by a
// frame that fails or breaks the stream. The events already decoded from
// that chunk must reach the client before the failure does, not be dropped
// with it.
#[tokio::test]
async fn a_failure_sharing_a_chunk_with_text_does_not_drop_the_text() {
    let dir = tempfile::tempdir().unwrap();
    let mut raw = frames(&[("assistantResponseEvent", r#"{"content":"hello"}"#)]);
    raw.extend(encode_exception_frame(
        "InternalServerException",
        br#"{"message":"boom"}"#,
    ));
    // The whole response arrives as one chunk, so the pump discovers the
    // text and the exception in the same `next()` call, at prime time
    // (before any other output): this must be a 200 with the text and the
    // error event, not an HTTP error.
    let (app, _) = app_with_chunk_size(dir.path(), vec![Ok(raw)], usize::MAX);
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let text = body_string(r).await;
    let text_pos = text.find("\"text\":\"hello\"").expect("text delta present");
    let error_pos = text.find("event: error").expect("error event present");
    assert!(text_pos < error_pos, "text must precede the error event");
}

#[tokio::test]
async fn a_failure_sharing_a_later_chunk_with_text_does_not_drop_the_text() {
    let dir = tempfile::tempdir().unwrap();
    // A long first frame primes the stream with real output. The second and
    // third frames (more text, then an exception) are kept short enough
    // that, chunked at exactly the first frame's byte length, they land
    // together in the *next* chunk: the failure now surfaces from the
    // ongoing `next()` loop in `stream_response`, not from `prime()`.
    let frame1 = encode_event_frame(
        "assistantResponseEvent",
        format!("{{\"content\":\"{}\"}}", "z".repeat(500)).as_bytes(),
    );
    let frame2 = encode_event_frame("assistantResponseEvent", br#"{"content":"more"}"#);
    let frame3 = encode_exception_frame("InternalServerException", br#"{"message":"boom"}"#);
    let rest_len = frame2.len() + frame3.len();
    assert!(
        frame1.len() >= rest_len,
        "test setup: frame1 ({} bytes) must be at least as long as frame2+frame3 ({rest_len} bytes)",
        frame1.len()
    );
    let mut raw = frame1.clone();
    raw.extend(&frame2);
    raw.extend(&frame3);
    let (app, _) = app_with_chunk_size(dir.path(), vec![Ok(raw)], frame1.len());
    // `max_tokens` well above the 500-char padding frame's estimated token
    // count (~125, at the translator's 4-chars-per-token local enforcement):
    // a `max_tokens` local stop must not cut this test's setup short before
    // the exception frame is even reached.
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 1000, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let text = body_string(r).await;
    let more_pos = text
        .find("\"text\":\"more\"")
        .expect("second text delta present");
    let error_pos = text.find("event: error").expect("error event present");
    assert!(more_pos < error_pos, "text must precede the error event");
}

#[tokio::test]
async fn a_broken_frame_sharing_a_chunk_with_text_does_not_drop_the_text() {
    let dir = tempfile::tempdir().unwrap();
    let mut raw = frames(&[("assistantResponseEvent", r#"{"content":"hello"}"#)]);
    // 12 zero bytes parse as a syntactically complete prelude (enough bytes
    // present) with a CRC of 0, which the real CRC of 8 zero bytes never
    // matches: a `FrameError::PreludeCrc`, decoded in the same read as the
    // valid text frame above.
    raw.extend([0u8; 12]);
    let (app, _) = app_with_chunk_size(dir.path(), vec![Ok(raw)], usize::MAX);
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let text = body_string(r).await;
    let text_pos = text.find("\"text\":\"hello\"").expect("text delta present");
    let error_pos = text.find("event: error").expect("error event present");
    assert!(text_pos < error_pos, "text must precede the error event");
}

#[tokio::test]
async fn retryable_invalid_state_clears_the_conversation_id_once() {
    {
        let dir = tempfile::tempdir().unwrap();
        let first = frames(&[(
            "invalidStateEvent",
            r#"{"reason":"STALE_CONVERSATION","message":"stale"}"#,
        )]);
        let second = frames(&[("assistantResponseEvent", r#"{"content":"ok"}"#)]);
        let (app, scripted) = app(dir.path(), vec![Ok(first), Ok(second)]);
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(body_string(r).await.contains("\"text\":\"ok\""));
        let p = scripted.payloads.lock().unwrap();
        assert_eq!(p.len(), 2);
        assert!(p[0]["conversationState"]["conversationId"].is_string());
        assert!(p[1]["conversationState"].get("conversationId").is_none());
    }

    {
        let dir = tempfile::tempdir().unwrap();
        let bad = frames(&[(
            "invalidStateEvent",
            r#"{"reason":"SOMETHING_ELSE","message":"no"}"#,
        )]);
        let (app, _) = app(dir.path(), vec![Ok(bad)]);
        let r = app
            .oneshot(messages_req(
                serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    }
}

// A second retryable invalid state must not trigger a second retry (spec
// 5.4: at most one). With only two responses queued, a regression that
// retried twice would panic on `Scripted::generate`'s `remove(0)` against an
// empty vec rather than fail this assertion.
#[tokio::test]
async fn a_second_retryable_invalid_state_is_not_retried_again() {
    let dir = tempfile::tempdir().unwrap();
    let first = frames(&[(
        "invalidStateEvent",
        r#"{"reason":"STALE_CONVERSATION","message":"stale"}"#,
    )]);
    let second = frames(&[(
        "invalidStateEvent",
        r#"{"reason":"STALE_CONVERSATION","message":"stale again"}"#,
    )]);
    let (app, scripted) = app(dir.path(), vec![Ok(first), Ok(second)]);
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        scripted.payloads.lock().unwrap().len(),
        2,
        "exactly two upstream calls: the retry, and no more"
    );
}

// Important 2: on the non-streaming path, nothing reaches the client until
// the whole response is folded, so a retryable invalid state must still get
// its one retry even after a content event (a `reasoningContentEvent`, say)
// was already translated internally. Before this fix, `Pump::prime` treated
// any buffered translator events as "output started" regardless of path,
// so it returned `Primed::Ready` on the content event and the invalid state
// discovered afterward, inside the non-streaming fold loop, had no retry
// path at all.
#[tokio::test]
async fn non_streaming_retries_a_retryable_invalid_state_after_a_content_event() {
    let dir = tempfile::tempdir().unwrap();
    let first = frames(&[
        ("reasoningContentEvent", r#"{"text":"t","signature":"s"}"#),
        (
            "invalidStateEvent",
            r#"{"reason":"STALE_CONVERSATION","message":"stale"}"#,
        ),
    ]);
    let second = frames(&[("assistantResponseEvent", r#"{"content":"ok"}"#)]);
    let (app, scripted) = app(dir.path(), vec![Ok(first), Ok(second)]);
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    assert_eq!(
        v["content"].as_array().unwrap().last().unwrap()["text"],
        "ok"
    );
    let p = scripted.payloads.lock().unwrap();
    assert_eq!(p.len(), 2, "the retry actually happened");
    assert!(p[0]["conversationState"]["conversationId"].is_string());
    assert!(
        p[1]["conversationState"].get("conversationId").is_none(),
        "the retry clears the conversation id"
    );
}

// Important 2, second half of the one-retry bound: a retryable invalid
// state after a content event on the FIRST attempt retries once; a second
// one on the retry attempt (also after a content event) must still end in
// the HTTP error after exactly two upstream calls, not a second retry.
#[tokio::test]
async fn non_streaming_two_retryable_invalid_states_after_content_events_return_the_http_error_once()
 {
    let dir = tempfile::tempdir().unwrap();
    let attempt = || {
        frames(&[
            ("reasoningContentEvent", r#"{"text":"t","signature":"s"}"#),
            (
                "invalidStateEvent",
                r#"{"reason":"STALE_CONVERSATION","message":"stale"}"#,
            ),
        ])
    };
    let (app, scripted) = app(dir.path(), vec![Ok(attempt()), Ok(attempt())]);
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        scripted.payloads.lock().unwrap().len(),
        2,
        "exactly two upstream calls: the retry, and no more"
    );
}

#[tokio::test]
async fn local_stop_drops_the_rest_of_the_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app(
        dir.path(),
        vec![Ok(frames(&[
            ("assistantResponseEvent", r#"{"content":"one END two"}"#),
            ("assistantResponseEvent", r#"{"content":"three"}"#),
        ]))],
    );
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "stream": true, "stop_sequences": ["END"], "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    let text = body_string(r).await;
    assert!(text.contains("\"text\":\"one \""));
    assert!(!text.contains("three"));
    assert!(text.contains("\"stop_sequence\":\"END\""));
}

#[tokio::test]
async fn concurrency_cap_returns_429() {
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(1)).unwrap());
    let tokens = Arc::new(TokenSource::new(test_db(dir.path()), net, None));
    let scripted = Arc::new(Scripted {
        responses: Mutex::new(vec![]),
        payloads: Mutex::new(vec![]),
        chunk_size: 7,
    });
    let limiter = Arc::new(tokio::sync::Semaphore::new(1));
    let state = Arc::new(AppState {
        tokens,
        upstream: scripted,
        local_token: SecretString::from(TOKEN.to_string()),
        limiter: limiter.clone(),
        conversation_salt: [1u8; 16],
    });
    let app = build_router(state);
    let _held = limiter.acquire().await.unwrap();
    let r = app
        .oneshot(messages_req(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
}

// Important 3: pins both the hold and the release of the streaming permit
// (spec 5.5), not just that an exhausted semaphore returns 429. A refactor
// that moved the permit back to a `let _permit` local dropped at the end of
// the handler (releasing it before the SSE body is ever read) would still
// pass `concurrency_cap_returns_429`, since that test never holds a
// streaming response open; it would fail the middle assertion here.
#[tokio::test]
async fn streaming_permit_is_held_for_the_connection_and_released_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(1)).unwrap());
    let tokens = Arc::new(TokenSource::new(test_db(dir.path()), net, None));
    let scripted = Arc::new(Scripted {
        responses: Mutex::new(vec![
            Ok(frames(&[(
                "assistantResponseEvent",
                r#"{"content":"first"}"#,
            )])),
            Ok(frames(&[(
                "assistantResponseEvent",
                r#"{"content":"third"}"#,
            )])),
        ]),
        payloads: Mutex::new(vec![]),
        chunk_size: 7,
    });
    let limiter = Arc::new(tokio::sync::Semaphore::new(1));
    let state = Arc::new(AppState {
        tokens,
        upstream: scripted,
        local_token: SecretString::from(TOKEN.to_string()),
        limiter: limiter.clone(),
        conversation_salt: [4u8; 16],
    });
    let app = build_router(state);
    let stream_req = || {
        messages_req(serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 10,
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
    };

    // Hold the first response without consuming its body. `Body::from_stream`
    // stores the `stream::unfold` state (which carries the permit) eagerly,
    // not lazily on first poll, so the permit is held from this point on.
    let first = app.clone().oneshot(stream_req()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // The one permit is still held by `first`: a second request is rejected.
    let second = app.clone().oneshot(stream_req()).await.unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers().get("retry-after").unwrap(), "1");

    // Dropping `first` drops its body's stream state, and with it the
    // permit. `tokio::sync::Semaphore`'s permit release runs synchronously
    // in `Drop`, so no delay is needed before the next acquire observes it.
    drop(first);

    let third = app.clone().oneshot(stream_req()).await.unwrap();
    assert_eq!(third.status(), StatusCode::OK);
}

/// An upstream that starts a stream but never yields a byte. The priming
/// deadline (Important 3) is the only thing that can end a request against
/// it; without it, this would hang the request (and the permit it holds)
/// forever.
struct Stalled;

#[async_trait::async_trait]
impl Upstream for Stalled {
    async fn generate(&self, _payload: &Payload) -> Result<UpstreamStream, UpstreamError> {
        Ok(UpstreamStream {
            attempts: 1,
            bytes: futures_util::stream::pending().boxed(),
        })
    }
}

// Important 3: a slow-trickling (here, fully stalled) upstream must not pin
// a concurrency permit indefinitely before any output exists.
// `#[tokio::test(start_paused = true)]` starts the runtime's virtual clock
// paused; when the only work left is a timer, tokio auto-advances the clock
// to it, so this observes `pump::PRIMING_DEADLINE` firing without a real
// 120 s wait. On expiry the request must fail and the permit must release.
#[tokio::test(start_paused = true)]
async fn a_stalled_upstream_fails_after_the_priming_deadline_and_releases_the_permit() {
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(1)).unwrap());
    let tokens = Arc::new(TokenSource::new(test_db(dir.path()), net, None));
    let limiter = Arc::new(tokio::sync::Semaphore::new(1));
    let state = Arc::new(AppState {
        tokens,
        upstream: Arc::new(Stalled),
        local_token: SecretString::from(TOKEN.to_string()),
        limiter: limiter.clone(),
        conversation_salt: [9u8; 16],
    });
    let app = build_router(state);
    let r = app
        .oneshot(messages_req(serde_json::json!({
            "model": "claude-sonnet-4-6", "max_tokens": 10,
            "messages": [{"role": "user", "content": "hi"}]
        })))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        limiter.available_permits(),
        1,
        "the permit is released once the priming deadline fails the request"
    );
}

#[tokio::test]
async fn count_tokens_is_offline_and_validates_the_model() {
    let dir = tempfile::tempdir().unwrap();
    let (app, scripted) = app(dir.path(), vec![]);
    let r = app
        .clone()
        .oneshot(
            Request::post("/v1/messages/count_tokens")
                .header("x-api-key", TOKEN)
                .body(Body::from(
                    serde_json::json!({"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "hello world"}]})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    assert!(v["input_tokens"].as_u64().unwrap() >= 3);
    assert!(
        scripted.payloads.lock().unwrap().is_empty(),
        "no upstream call"
    );
    let r = app
        .oneshot(
            Request::post("/v1/messages/count_tokens")
                .header("x-api-key", TOKEN)
                .body(Body::from(
                    serde_json::json!({"model": "nope", "messages": [{"role": "user", "content": "x"}]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

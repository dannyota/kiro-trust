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
        // Deliver in 7-byte chunks so frame seams cross chunk boundaries.
        let chunks: Vec<Result<bytes::Bytes, UpstreamError>> = bytes
            .chunks(7)
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
    let net = Arc::new(Client::new(Policy::loopback_plain_http(1)).unwrap());
    let tokens = Arc::new(TokenSource::new(test_db(dir), net, None));
    let scripted = Arc::new(Scripted {
        responses: Mutex::new(responses),
        payloads: Mutex::new(vec![]),
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
        StatusCode::BAD_REQUEST,
        "spec 5.6: 400 invalid_request_error, not axum's 413"
    );
    assert_eq!(r.headers()["content-type"], "application/json");
    let body = body_string(r).await;
    assert!(body.contains("\"invalid_request_error\""));
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

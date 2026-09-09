//! Live tier (spec 8.6): reads the real Kiro database on this machine and
//! makes real calls to the Kiro runtime. Ignored by default.
//!
//! Run the ordinary live tests:
//!   KIRO_TRUST_LIVE=1 cargo test -p kiro-trust-tests --test live -- --ignored --test-threads=1
//!
//! `forced_refresh_succeeds` needs a second, explicit opt-in on top of that
//! (see the comment on the test itself) because it forces a real OIDC
//! refresh against the owner's Identity Center credential:
//!   KIRO_TRUST_LIVE=1 KIRO_TRUST_LIVE_REFRESH=1 cargo test -p kiro-trust-tests --test live -- --ignored --test-threads=1
//!
//! Every test here asserts structure, status, and counts only, and prints
//! byte counts, token counts, and durations only (spec 8.6, task-21-rulings
//! ruling 3). Never assert on model wording, and never print or include a
//! prompt, a response body, a conversation id, a token, an ARN, or an
//! account id in an assertion message.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use kiro_trust::server::{AppState, build_router};
use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::KiroClient;
use kiro_trust_net::{Client, Policy};
use secrecy::SecretString;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn live() -> bool {
    std::env::var("KIRO_TRUST_LIVE").as_deref() == Ok("1")
}

/// Second, explicit opt-in for `forced_refresh_succeeds` (task-21-rulings
/// ruling 1), independent of `KIRO_TRUST_LIVE`.
fn live_refresh() -> bool {
    std::env::var("KIRO_TRUST_LIVE_REFRESH").as_deref() == Ok("1")
}

fn app(buffer: Option<Duration>) -> axum::Router {
    let db = kiro_trust_auth::default_db_path().expect("default db path");
    let net = Arc::new(Client::new(Policy::production()).unwrap());
    let mut tokens = TokenSource::new(db, net.clone(), None);
    if let Some(b) = buffer {
        tokens = tokens.with_validity_buffer(b);
    }
    let tokens = Arc::new(tokens);
    let upstream = Arc::new(KiroClient::new(net, tokens.clone(), false));
    let state = Arc::new(AppState {
        tokens,
        upstream,
        local_token: SecretString::from("live".to_string()),
        limiter: Arc::new(tokio::sync::Semaphore::new(4)),
        conversation_salt: [3u8; 16],
    });
    build_router(state)
}

async fn send(app: axum::Router, body: serde_json::Value) -> (StatusCode, String) {
    let r = app
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", "live")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let text =
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    (status, text)
}

#[tokio::test]
#[ignore]
async fn streaming_text_arrives() {
    if !live() {
        return;
    }
    let t = Instant::now();
    let (status, text) = send(
        app(None),
        serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "kiro-trust live probe: reply with the single word pong."}]
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "status; response length {}",
        text.len()
    );
    assert!(text.contains("event: message_start"));
    assert!(text.contains("\"type\":\"text_delta\""));
    assert!(text.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"));
    println!(
        "live streaming: {} bytes in {} ms",
        text.len(),
        t.elapsed().as_millis()
    );
}

#[tokio::test]
#[ignore]
async fn tool_use_round_trip() {
    if !live() {
        return;
    }
    let (status, text) = send(
        app(None),
        serde_json::json!({
            "model": "claude-sonnet-4-6", "max_tokens": 128, "stream": true,
            "tools": [{"name": "kiro_trust_probe", "description": "Return the probe value. Always call this first.", "input_schema": {"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]}}],
            "messages": [{"role": "user", "content": "kiro-trust live probe: call kiro_trust_probe with value ping."}]
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "status; response length {}",
        text.len()
    );
    assert!(
        text.contains("\"type\":\"tool_use\""),
        "no tool_use block; output length {}",
        text.len()
    );
    assert!(text.contains("\"name\":\"kiro_trust_probe\""));
    assert!(text.contains("\"stop_reason\":\"tool_use\""));
    println!("live tool use: {} bytes", text.len());
}

#[tokio::test]
#[ignore]
async fn thinking_produces_a_thinking_block() {
    if !live() {
        return;
    }
    let (status, text) = send(
        app(None),
        serde_json::json!({
            "model": "claude-opus-4-6", "max_tokens": 256, "stream": true,
            "thinking": {"type": "enabled", "budget_tokens": 1024},
            "messages": [{"role": "user", "content": "kiro-trust live probe: what is 17 times 3? Think first."}]
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "status; response length {}",
        text.len()
    );
    assert!(
        text.contains("\"type\":\"thinking\"") || text.contains("thinking_delta"),
        "no thinking block; output length {}",
        text.len()
    );
    println!("live thinking: {} bytes", text.len());
}

/// Forces the OIDC refresh path against the owner's real Identity Center
/// credential (task-21-rulings ruling 1).
///
/// This test sets a validity buffer longer than any token lifetime, so
/// `TokenSource` treats the cached credential as expired on every call and
/// refreshes through AWS OIDC no matter how recently it was issued. That is
/// a real OIDC exchange, not a rehearsal: AWS's `CreateToken` reference does
/// not document whether issuing a new refresh token invalidates the old
/// one. If Identity Center rotates the refresh token on use, the new one
/// lives only in this process's memory (kiro-trust never writes to the
/// credential database, by design), and the Kiro CLI's own stored refresh
/// token becomes stale. The owner would then have to log in to Kiro CLI
/// again to restore it. That is recoverable, not destructive, but it is a
/// change to state outside this repository, so this test needs a second,
/// explicit opt-in beyond `KIRO_TRUST_LIVE`: `KIRO_TRUST_LIVE_REFRESH=1`.
#[tokio::test]
#[ignore]
async fn forced_refresh_succeeds() {
    if !live() || !live_refresh() {
        return;
    }
    // A validity buffer longer than any token lifetime forces the OIDC
    // refresh path.
    let (status, text) = send(
        app(Some(Duration::from_secs(400 * 24 * 3600))),
        serde_json::json!({
            "model": "claude-sonnet-4-6", "max_tokens": 16, "stream": false,
            "messages": [{"role": "user", "content": "kiro-trust live probe: say ok."}]
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "refresh path failed; length {}",
        text.len()
    );
    println!("live refresh: ok");
}

#[tokio::test]
#[ignore]
async fn non_streaming_message() {
    if !live() {
        return;
    }
    let (status, text) = send(
        app(None),
        serde_json::json!({
            "model": "claude-haiku-4-5", "max_tokens": 32, "stream": false,
            "messages": [{"role": "user", "content": "kiro-trust live probe: say ok."}]
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "status; response length {}",
        text.len()
    );
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "message");
    assert!(v["usage"]["input_tokens"].as_u64().unwrap() > 0);
    println!(
        "live non-streaming: input_tokens={} output_tokens={}",
        v["usage"]["input_tokens"], v["usage"]["output_tokens"]
    );
}

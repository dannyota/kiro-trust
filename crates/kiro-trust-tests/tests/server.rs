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

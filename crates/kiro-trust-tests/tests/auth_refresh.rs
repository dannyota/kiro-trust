use kiro_trust_auth::{AuthError, TokenSource};
use kiro_trust_net::{Client, Policy};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Arc;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_db(dir: &std::path::Path, expires_at: &str) -> PathBuf {
    let p = dir.join("data.sqlite3");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT); CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB);").unwrap();
    let token = format!(
        r#"{{"access_token":"old-access","refresh_token":"old-refresh","expires_at":"{expires_at}","region":"ap-southeast-1"}}"#
    );
    c.execute(
        "INSERT INTO auth_kv VALUES ('kirocli:odic:token', ?1)",
        [token],
    )
    .unwrap();
    c.execute("INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{\"clientId\":\"cid\",\"clientSecret\":\"csec\"}')", []).unwrap();
    c.execute("INSERT INTO state VALUES ('api.codewhisperer.profile', '{\"arn\":\"arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE\"}')", []).unwrap();
    p
}

async fn source(server: &MockServer, db: PathBuf) -> TokenSource {
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    TokenSource::new(db, net, None)
}

#[tokio::test]
async fn valid_token_is_served_without_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = source(&server, make_db(dir.path(), "2099-01-01T00:00:00Z")).await;
    let t = src.with_token(|t| t.to_string()).await.unwrap();
    assert_eq!(t, "old-access");
    let id = src.identity().await.unwrap();
    assert_eq!(id.runtime_region.as_str(), "us-east-1");
    assert_eq!(id.sso_region.as_str(), "ap-southeast-1");
}

#[tokio::test]
async fn expired_token_is_refreshed_once_for_concurrent_callers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(serde_json::json!({"grantType": "refresh_token", "clientId": "cid", "clientSecret": "csec", "refreshToken": "old-refresh"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"accessToken": "new-access", "refreshToken": "new-refresh", "expiresIn": 3600})))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = Arc::new(source(&server, make_db(dir.path(), "2020-01-01T00:00:00Z")).await);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = src.clone();
        handles.push(tokio::spawn(async move {
            s.with_token(|t| t.to_string()).await.unwrap()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), "new-access");
    }
    // Cached now: the mock's expect(1) is verified on drop.
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "new-access"
    );
}

#[tokio::test]
async fn refresh_failure_is_an_error_and_invalidate_forces_reread() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_string("{\"error\":\"invalid_grant\"}"))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = source(&server, make_db(dir.path(), "2020-01-01T00:00:00Z")).await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::RefreshRejected { status: 400 }));
    assert!(
        !format!("{err}").contains("invalid_grant"),
        "response bodies are never surfaced"
    );

    // A fresh login lands in the database; invalidate picks it up without refresh.
    let c = Connection::open(dir.path().join("data.sqlite3")).unwrap();
    c.execute("UPDATE auth_kv SET value = '{\"access_token\":\"relogin\",\"refresh_token\":\"r\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"region\":\"ap-southeast-1\"}' WHERE key = 'kirocli:odic:token'", []).unwrap();
    src.invalidate().await;
    assert_eq!(src.with_token(|t| t.to_string()).await.unwrap(), "relogin");
}

#[tokio::test]
async fn absurd_expires_in_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"accessToken": "a", "expiresIn": 9223372036854775807i64}),
        ))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = source(&server, make_db(dir.path(), "2020-01-01T00:00:00Z")).await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::Refresh(_)), "{err}");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"accessToken": "a", "expiresIn": 0})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = source(&server, make_db(dir.path(), "2020-01-01T00:00:00Z")).await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::Refresh(_)), "{err}");
}

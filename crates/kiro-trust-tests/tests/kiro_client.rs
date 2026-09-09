use futures_util::StreamExt;
use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::{KiroClient, Upstream, UpstreamErrorKind, headers};
use kiro_trust_net::{Client, Policy};
use kiro_trust_protocol::eventstream::encode_event_frame;
use kiro_trust_protocol::kiro::*;
use rusqlite::Connection;
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn db(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("data.sqlite3");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT); CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB);").unwrap();
    c.execute("INSERT INTO auth_kv VALUES ('kirocli:odic:token', '{\"access_token\":\"tok\",\"refresh_token\":\"r\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"region\":\"us-east-1\"}')", []).unwrap();
    c.execute("INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{\"clientId\":\"c\",\"clientSecret\":\"s\"}')", []).unwrap();
    c.execute("INSERT INTO state VALUES ('api.codewhisperer.profile', 'arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE')", []).unwrap();
    p
}

fn payload() -> Payload {
    Payload {
        conversation_state: ConversationState {
            conversation_id: None,
            chat_trigger_type: CHAT_TRIGGER_MANUAL,
            agent_task_type: AGENT_TASK_VIBE,
            current_message: CurrentMessage {
                user_input_message: UserInputMessage {
                    content: "hi".into(),
                    model_id: None,
                    origin: None,
                    user_input_message_context: None,
                    images: vec![],
                    cache_point: None,
                },
            },
            history: vec![],
        },
        profile_arn: None,
        additional_model_request_fields: None,
    }
}

async fn client(server: &MockServer, dir: &std::path::Path, share: bool) -> KiroClient {
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    let tokens = Arc::new(TokenSource::new(db(dir), net.clone(), None));
    KiroClient::new(net, tokens, share).with_base_delay(Duration::from_millis(1))
}

fn stream_body() -> Vec<u8> {
    encode_event_frame("assistantResponseEvent", br#"{"content":"ok"}"#)
}

// kirocc TestHTTPClient_CorrectHeaders, TestAmzSdkRequestHeader; spec 7.4
#[tokio::test]
async fn sends_the_pinned_headers_and_streams_the_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("authorization", "Bearer tok"))
        .and(header("content-type", "application/x-amz-json-1.0"))
        .and(header("x-amz-target", headers::AMZ_TARGET))
        .and(header("user-agent", headers::USER_AGENT))
        .and(header("x-amz-user-agent", headers::AMZ_USER_AGENT))
        .and(header("x-amzn-codewhisperer-optout", "true"))
        .and(header("amz-sdk-request", "attempt=1; max=3"))
        .and(header_exists("amz-sdk-invocation-id"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.amazon.eventstream")
                .set_body_bytes(stream_body()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let c = client(&server, dir.path(), false).await;
    let mut s = c.generate(&payload()).await.unwrap();
    assert_eq!(s.attempts, 1);
    let mut bytes = Vec::new();
    while let Some(chunk) = s.bytes.next().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(bytes, stream_body());
}

#[tokio::test]
async fn share_content_flag_sends_optout_false() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-amzn-codewhisperer-optout", "false"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.amazon.eventstream")
                .set_body_bytes(stream_body()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    client(&server, dir.path(), true)
        .await
        .generate(&payload())
        .await
        .unwrap();
}

struct Sequence(std::sync::Mutex<Vec<ResponseTemplate>>);
impl Respond for Sequence {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let mut v = self.0.lock().unwrap();
        if v.len() > 1 {
            v.remove(0)
        } else {
            v[0].clone()
        }
    }
}
fn ok() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/vnd.amazon.eventstream")
        .set_body_bytes(stream_body())
}

// kirocc TestHTTPClient_Retry429, TestHTTPClient_NonEventStreamThrottlingRetries, TestHTTPClient_Retry403_WithRefresh, _400_NoRetry
#[tokio::test]
async fn retries_throttling_server_errors_and_json_exceptions_but_not_client_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Sequence(std::sync::Mutex::new(vec![
            ResponseTemplate::new(429).set_body_string("{\"__type\":\"ThrottlingException\"}"),
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    "{\"__type\":\"com.amazon#InternalServerException\",\"message\":\"boom\"}",
                ),
            ok(),
        ])))
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let s = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap();
    assert_eq!(s.attempts, 3);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429).set_body_string("{\"__type\":\"ThrottlingException\"}"),
        )
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let err = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(err.kind, UpstreamErrorKind::Throttled);
    assert_eq!(err.exception_type.as_deref(), Some("ThrottlingException"));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("{\"__type\":\"ValidationException\",\"message\":\"bad\"}"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let err = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(err.kind, UpstreamErrorKind::Client);
    assert_eq!(err.status, Some(400));
    assert_eq!(err.message, "bad");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Sequence(std::sync::Mutex::new(vec![
            ResponseTemplate::new(403),
            ok(),
        ])))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let s = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap();
    assert_eq!(s.attempts, 2, "403 invalidates the token and retries once");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let err = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(err.kind, UpstreamErrorKind::Auth);
}

// A 403 on the last of the three attempts must not extend the loop to a
// fourth request: the general three-attempt bound wins over the 403 retry.
#[tokio::test]
async fn mixed_retries_never_exceed_three_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Sequence(std::sync::Mutex::new(vec![
            ResponseTemplate::new(500).set_body_string("{\"__type\":\"InternalServerException\"}"),
            ResponseTemplate::new(500).set_body_string("{\"__type\":\"InternalServerException\"}"),
            ResponseTemplate::new(403),
        ])))
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let err = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(err.kind, UpstreamErrorKind::Auth);
    assert_eq!(err.status, Some(403));
}

#[tokio::test]
async fn error_messages_are_capped_at_1_kib() {
    let server = MockServer::start().await;
    let long = "x".repeat(5000);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_string(format!(
            "{{\"__type\":\"ValidationException\",\"message\":\"{long}\"}}"
        )))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let err = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(err.message.len(), 1024);
}

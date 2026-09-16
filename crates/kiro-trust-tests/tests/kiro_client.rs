use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue};
use httpdate::fmt_http_date;
use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::{
    AttemptProgress, KiroClient, RetryDelay, Upstream, UpstreamErrorKind, classify_throttle,
    headers, retry_after,
};
use kiro_trust_net::{Client, Policy};
use kiro_trust_protocol::eventstream::encode_event_frame;
use kiro_trust_protocol::kiro::*;
use rusqlite::Connection;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
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
    client_at(server.address().port(), dir, share).await
}

async fn client_at(port: u16, dir: &std::path::Path, share: bool) -> KiroClient {
    client_at_with_base_delay(port, dir, share, Duration::from_millis(1)).await
}

async fn client_at_with_base_delay(
    port: u16,
    dir: &std::path::Path,
    share: bool,
    base_delay: Duration,
) -> KiroClient {
    let net = Arc::new(Client::new(Policy::loopback_plain_http(port)).unwrap());
    let tokens = Arc::new(TokenSource::new(db(dir), net.clone(), None));
    KiroClient::new(net, tokens, share).with_base_delay(base_delay)
}

fn stream_body() -> Vec<u8> {
    encode_event_frame("assistantResponseEvent", br#"{"content":"ok"}"#)
}

async fn wait_for_progress(progress: &AttemptProgress, expected: u32) {
    for _ in 0..100 {
        if progress.completed() == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("progress did not reach {expected}");
}

async fn receive_without_advancing_time<T>(
    receiver: &mut oneshot::Receiver<T>,
    expected: &str,
) -> T {
    for _ in 0..100 {
        match receiver.try_recv() {
            Ok(value) => return value,
            Err(oneshot::error::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(oneshot::error::TryRecvError::Closed) => {
                panic!("synthetic server closed before {expected}")
            }
        }
    }
    panic!("synthetic server did not report {expected} without advancing time");
}

async fn assert_not_received_without_advancing_time<T>(
    receiver: &mut oneshot::Receiver<T>,
    unexpected: &str,
) {
    for _ in 0..100 {
        match receiver.try_recv() {
            Ok(_) => panic!("{unexpected} arrived before its Retry-After delay"),
            Err(oneshot::error::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(oneshot::error::TryRecvError::Closed) => {
                panic!("synthetic server closed before {unexpected}")
            }
        }
    }
}

async fn assert_retry_after_schedule<F>(
    retry_after: F,
    no_retry_before: Duration,
    retry_at: Duration,
) where
    F: FnOnce() -> String + Send + 'static,
{
    let started = tokio::time::Instant::now();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let client = Arc::new(
        client_at_with_base_delay(
            listener.local_addr().unwrap().port(),
            dir.path(),
            false,
            Duration::from_secs(10),
        )
        .await,
    );
    let (first_consumed, mut first_consumed_receiver) = oneshot::channel();
    let (second_started, mut second_started_receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let retry_after = retry_after();
        first
            .write_all(
                format!(
                    "HTTP/1.1 429 Too Many Requests\r\nretry-after: {retry_after}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        first.shutdown().await.unwrap();
        let mut discarded_request = Vec::new();
        first.read_to_end(&mut discarded_request).await.unwrap();
        first_consumed.send(()).unwrap();
        let (_second, _) = listener.accept().await.unwrap();
        second_started.send(()).unwrap();
    });
    let task = tokio::spawn({
        let client = client.clone();
        async move { client.generate(&payload()).await }
    });

    receive_without_advancing_time(
        &mut first_consumed_receiver,
        "the first response consumption",
    )
    .await;
    assert_eq!(tokio::time::Instant::now() - started, Duration::ZERO);
    tokio::time::advance(no_retry_before).await;
    assert_not_received_without_advancing_time(&mut second_started_receiver, "second request")
        .await;
    tokio::time::advance(retry_at - no_retry_before).await;
    receive_without_advancing_time(&mut second_started_receiver, "the second request").await;
    assert_eq!(tokio::time::Instant::now() - started, retry_at);

    task.abort();
    let _ = task.await;
    server.abort();
    let _ = server.await;
}

#[test]
fn classifier_and_retry_after_keep_only_normalized_values() {
    assert_eq!(
        classify_throttle(429, b"INSUFFICIENT_MODEL_CAPACITY"),
        UpstreamErrorKind::ModelCapacity
    );
    assert_eq!(
        classify_throttle(429, b"quota limit"),
        UpstreamErrorKind::Throttled
    );

    let mut headers = HeaderMap::new();
    headers.insert("retry-after", HeaderValue::from_static("7"));
    assert_eq!(
        retry_after(&headers, std::time::SystemTime::UNIX_EPOCH),
        RetryDelay::Wait(Duration::from_secs(7))
    );

    headers.insert("retry-after", HeaderValue::from_static("61"));
    assert_eq!(
        retry_after(&headers, std::time::SystemTime::UNIX_EPOCH),
        RetryDelay::Stop(Some(Duration::from_secs(61)))
    );

    headers.insert(
        "retry-after",
        HeaderValue::from_static("Thu, 01 Jan 1970 00:01:01 GMT"),
    );
    assert_eq!(
        retry_after(
            &headers,
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        ),
        RetryDelay::Wait(Duration::from_secs(60))
    );

    headers.insert("retry-after", HeaderValue::from_static("not a delay"));
    assert_eq!(
        retry_after(&headers, std::time::SystemTime::UNIX_EPOCH),
        RetryDelay::Fallback
    );
    headers.insert("retry-after", HeaderValue::from_static(""));
    assert_eq!(
        retry_after(&headers, std::time::SystemTime::UNIX_EPOCH),
        RetryDelay::Fallback
    );
    headers.insert(
        "retry-after",
        HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"),
    );
    assert_eq!(
        retry_after(
            &headers,
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1)
        ),
        RetryDelay::Fallback
    );

    headers.insert(
        "retry-after",
        HeaderValue::from_static("184467440737095516160000"),
    );
    assert_eq!(
        retry_after(&headers, std::time::SystemTime::UNIX_EPOCH),
        RetryDelay::Stop(None)
    );
}

#[tokio::test]
async fn default_progress_records_returned_attempts_once() {
    struct Once;

    #[async_trait::async_trait]
    impl Upstream for Once {
        async fn generate(
            &self,
            _payload: &Payload,
        ) -> Result<kiro_trust_kiro::UpstreamStream, kiro_trust_kiro::UpstreamError> {
            Ok(kiro_trust_kiro::UpstreamStream {
                attempts: 2,
                bytes: futures_util::stream::empty().boxed(),
            })
        }
    }

    let progress = AttemptProgress::default();
    let stream = Once
        .generate_with_progress(&payload(), &progress)
        .await
        .unwrap();
    assert_eq!(stream.attempts, 2);
    assert_eq!(progress.completed(), 2);
}

#[tokio::test(start_paused = true)]
async fn progress_excludes_a_pending_first_post_when_cancelled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let client =
        Arc::new(client_at(listener.local_addr().unwrap().port(), dir.path(), false).await);
    let progress = AttemptProgress::default();
    let task = tokio::spawn({
        let client = client.clone();
        let progress = progress.clone();
        async move { client.generate_with_progress(&payload(), &progress).await }
    });
    let (_pending, _) = listener.accept().await.unwrap();
    assert_eq!(progress.completed(), 0);
    task.abort();
    let _ = task.await;
    assert_eq!(progress.completed(), 0);
}

#[tokio::test(start_paused = true)]
async fn progress_retains_completed_posts_across_retry_cancellation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let client =
        Arc::new(client_at(listener.local_addr().unwrap().port(), dir.path(), false).await);
    let progress = AttemptProgress::default();
    let task = tokio::spawn({
        let client = client.clone();
        let progress = progress.clone();
        async move { client.generate_with_progress(&payload(), &progress).await }
    });

    let (mut first, _) = listener.accept().await.unwrap();
    first
        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 7\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    drop(first);
    wait_for_progress(&progress, 1).await;
    assert_eq!(progress.completed(), 1, "the first rejected post completed");
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    let pending = futures_util::future::poll_fn(|context| match listener.poll_accept(context) {
        Poll::Pending => Poll::Ready(true),
        Poll::Ready(Ok(_)) => Poll::Ready(false),
        Poll::Ready(Err(error)) => panic!("listener failed: {error}"),
    })
    .await;
    assert!(
        pending,
        "Retry-After: 7 must not start the second post after six seconds"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let (_pending, _) = listener.accept().await.unwrap();
    assert_eq!(progress.completed(), 1, "the second post is still pending");
    task.abort();
    let _ = task.await;
    assert_eq!(progress.completed(), 1);
}

#[tokio::test(start_paused = true)]
async fn progress_records_the_second_post_before_the_next_retry_sleep() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let client =
        Arc::new(client_at(listener.local_addr().unwrap().port(), dir.path(), false).await);
    let progress = AttemptProgress::default();
    let task = tokio::spawn({
        let client = client.clone();
        let progress = progress.clone();
        async move { client.generate_with_progress(&payload(), &progress).await }
    });

    let (mut first, _) = listener.accept().await.unwrap();
    first
        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 7\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    drop(first);
    wait_for_progress(&progress, 1).await;
    tokio::time::advance(Duration::from_secs(7)).await;
    let (mut second, _) = listener.accept().await.unwrap();
    second
        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 7\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    drop(second);
    wait_for_progress(&progress, 2).await;
    assert_eq!(progress.completed(), 2);
    task.abort();
    let _ = task.await;
    assert_eq!(progress.completed(), 2);
}

#[tokio::test(start_paused = true)]
async fn http_date_retry_after_waits_for_its_remaining_delay() {
    assert_retry_after_schedule(
        || fmt_http_date(SystemTime::now() + Duration::from_secs(7)),
        Duration::from_secs(6),
        Duration::from_secs(7),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn invalid_retry_after_uses_jitter_instead_of_a_zero_delay() {
    assert_retry_after_schedule(
        || "invalid".to_string(),
        Duration::from_secs(7),
        Duration::from_secs(13),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn past_retry_after_uses_jitter_instead_of_a_zero_delay() {
    assert_retry_after_schedule(
        || "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        Duration::from_secs(7),
        Duration::from_secs(13),
    )
    .await;
}

#[tokio::test]
async fn excessive_retry_after_stops_before_the_next_post_and_preserves_the_delay() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "61"))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 1);
    assert_eq!(error.kind, UpstreamErrorKind::Throttled);
    assert_eq!(error.retry_after, Some(Duration::from_secs(61)));
}

#[tokio::test]
async fn final_retry_attempt_keeps_a_normalized_excessive_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Sequence(std::sync::Mutex::new(vec![
            ResponseTemplate::new(429),
            ResponseTemplate::new(429),
            ResponseTemplate::new(429).insert_header("retry-after", "61"),
        ])))
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 3);
    assert_eq!(error.retry_after, Some(Duration::from_secs(61)));
}

#[tokio::test]
async fn capacity_marker_on_http_500_is_a_rate_limit_category() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("INSUFFICIENT_MODEL_CAPACITY"))
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 3);
    assert_eq!(error.kind, UpstreamErrorKind::ModelCapacity);
}

#[tokio::test]
async fn capacity_marker_on_http_503_is_a_rate_limit_category() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_body_string("INSUFFICIENT_MODEL_CAPACITY"))
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 3);
    assert_eq!(error.kind, UpstreamErrorKind::ModelCapacity);
}

#[tokio::test]
async fn malformed_non_eventstream_200_with_a_capacity_marker_is_protocol() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("INSUFFICIENT_MODEL_CAPACITY"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 1);
    assert_eq!(error.kind, UpstreamErrorKind::Protocol);
}

#[tokio::test]
async fn capacity_marker_in_a_json_exception_uses_the_same_category() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    r#"{"__type":"ValidationException","message":"INSUFFICIENT_MODEL_CAPACITY"}"#,
                ),
        )
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 3);
    assert_eq!(error.kind, UpstreamErrorKind::ModelCapacity);
}

fn monthly_limit_body() -> String {
    std::fs::read_to_string(
        kiro_trust_tests::fixtures_dir().join("errors/monthly-request-count/body.json"),
    )
    .unwrap()
}

// Recorded 400 body (tests/fixtures/errors/monthly-request-count).
#[tokio::test]
async fn recorded_monthly_limit_is_allowance_exhaustion_without_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/x-amz-json-1.0")
                .set_body_string(monthly_limit_body()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 1);
    assert_eq!(error.kind, UpstreamErrorKind::AllowanceExhausted);
    assert_eq!(error.status, Some(400));
    assert_eq!(
        error.exception_type.as_deref(),
        Some("ServiceQuotaExceededException")
    );
    assert_eq!(error.message, "You have reached the limit.");
    assert_eq!(error.retry_after, None);
}

#[tokio::test]
async fn other_400_bodies_stay_client_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            r#"{"__type":"ServiceQuotaExceededException","message":"You have reached the limit."}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.kind, UpstreamErrorKind::Client);
}

#[tokio::test]
async fn monthly_marker_on_a_429_stops_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_string(
                    r#"{"__type":"ThrottlingException","message":"x","reason":"MONTHLY_REQUEST_COUNT"}"#,
                ),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 1);
    assert_eq!(error.kind, UpstreamErrorKind::AllowanceExhausted);
    assert_eq!(error.retry_after, None);
}

#[tokio::test]
async fn monthly_marker_in_a_200_throttling_exception_stops_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    r#"{"__type":"ThrottlingException","message":"x","reason":"MONTHLY_REQUEST_COUNT"}"#,
                ),
        )
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 1);
    assert_eq!(error.kind, UpstreamErrorKind::AllowanceExhausted);
}

#[tokio::test]
async fn capacity_marker_outranks_the_monthly_marker() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_string(
            r#"{"__type":"ThrottlingException","message":"INSUFFICIENT_MODEL_CAPACITY","reason":"MONTHLY_REQUEST_COUNT"}"#,
        ))
        .expect(3)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.attempts, 3);
    assert_eq!(error.kind, UpstreamErrorKind::ModelCapacity);
}

#[tokio::test]
async fn pre_send_header_failure_reports_zero_attempts() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = db(dir.path());
    let connection = Connection::open(db_path).unwrap();
    connection
        .execute(
            "UPDATE auth_kv SET value = ?1 WHERE key = 'kirocli:odic:token'",
            [r#"{"access_token":"bad\nheader","refresh_token":"r","expires_at":"2099-01-01T00:00:00Z","region":"us-east-1"}"#],
        )
        .unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    let tokens = Arc::new(TokenSource::new(
        dir.path().join("data.sqlite3"),
        net.clone(),
        None,
    ));
    let error = KiroClient::new(net, tokens, false)
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.kind, UpstreamErrorKind::Auth);
    assert_eq!(error.attempts, 0);
}

#[tokio::test]
async fn redirect_and_transport_errors_count_completed_posts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(302))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let redirect = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(redirect.attempts, 1);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let dir = tempfile::tempdir().unwrap();
    let transport = client_at(port, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(transport.kind, UpstreamErrorKind::Transport);
    assert_eq!(transport.attempts, 3);
}

#[tokio::test]
async fn failed_refresh_after_a_403_preserves_the_one_completed_post() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let error = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap_err();
    assert_eq!(error.kind, UpstreamErrorKind::Auth);
    assert_eq!(error.attempts, 1);
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

/// A refresh response `db()`'s "r" refresh token can be exchanged for
/// without needing a fresh `TokenSource`: `db()`'s stored credential is
/// valid until 2099 and unrefreshed, so it is never `minted_by_refresh`
/// (spec 3.3), and a forced cycle after a 403 is therefore free to refresh
/// it rather than being bound to re-serving it (FIX 2).
fn oidc_refresh_ok() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "accessToken": "tok2", "refreshToken": "r2", "expiresIn": 3600
    }))
}

// kirocc TestHTTPClient_Retry429, TestHTTPClient_NonEventStreamThrottlingRetries, TestHTTPClient_Retry403_WithRefresh, _400_NoRetry
#[tokio::test]
async fn retries_throttling_server_errors_and_json_exceptions_but_not_client_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
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
        .and(path("/"))
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
    assert_eq!(err.attempts, 3);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
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
    assert_eq!(err.attempts, 1);

    // A 403 forces a cycle (spec 3.3). `db()`'s credential was never
    // refreshed, so the forced-cycle bound (FIX 2) does not apply: the
    // cycle refreshes it, and attempt 2's runtime POST carries whatever
    // that refresh returns. Both endpoints get their own mock and their
    // own count, so a stray call to either fails the test.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(Sequence(std::sync::Mutex::new(vec![
            ResponseTemplate::new(403),
            ok(),
        ])))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oidc_refresh_ok())
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let s = client(&server, dir.path(), false)
        .await
        .generate(&payload())
        .await
        .unwrap();
    assert_eq!(s.attempts, 2, "403 invalidates the token and retries once");

    // A 403 on every runtime attempt. The forced cycle after attempt 1
    // refreshes exactly once (same reasoning as above) and succeeds, so
    // attempt 2's runtime POST actually happens and is also rejected,
    // reaching client.rs's own terminal-403 branch: `status` is asserted
    // to be `Some(403)` specifically so a coincidental Auth-kind error from
    // the auth layer (as would happen if the refresh above failed instead)
    // cannot pass this test for the wrong reason.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(oidc_refresh_ok())
        .expect(1)
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
    assert_eq!(err.attempts, 2);
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
    assert_eq!(err.attempts, 3);
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

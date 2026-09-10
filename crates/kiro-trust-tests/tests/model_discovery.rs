use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::{DiscoveryClient, DiscoveryError};
use kiro_trust_net::{
    Client, Destination, DiscoveryRegion, ModelDiscoveryQuery, Policy, SensitiveBearer,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

struct Sequence(std::sync::Mutex<Vec<ResponseTemplate>>);

impl Respond for Sequence {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let mut responses = self.0.lock().unwrap();
        if responses.len() > 1 {
            responses.remove(0)
        } else {
            responses[0].clone()
        }
    }
}

struct RecordingSequence {
    requests: Arc<Mutex<Vec<Request>>>,
    responses: Mutex<Vec<ResponseTemplate>>,
}

impl Respond for RecordingSequence {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.requests.lock().unwrap().push(request.clone());
        let mut responses = self.responses.lock().unwrap();
        if responses.len() > 1 {
            responses.remove(0)
        } else {
            responses[0].clone()
        }
    }
}

fn make_db(dir: &std::path::Path, expires_at: &str) -> std::path::PathBuf {
    make_db_with_profile(
        dir,
        expires_at,
        Some("arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE"),
    )
}

fn make_db_with_profile(
    dir: &std::path::Path,
    expires_at: &str,
    profile_arn: Option<&str>,
) -> std::path::PathBuf {
    let path = dir.join("data.sqlite3");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT);\
             CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB);",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO auth_kv VALUES ('kirocli:odic:token', ?1)",
            [format!(
                r#"{{"access_token":"fixture-access","refresh_token":"fixture-refresh","expires_at":"{expires_at}","region":"us-east-1"}}"#
            )],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{\"clientId\":\"fixture-client\",\"clientSecret\":\"fixture-secret\"}')",
            [],
        )
        .unwrap();
    if let Some(profile_arn) = profile_arn {
        connection
            .execute(
                "INSERT INTO state VALUES ('api.codewhisperer.profile', ?1)",
                [format!(r#"{{"arn":"{profile_arn}"}}"#)],
            )
            .unwrap();
    }
    path
}

struct ControlledRequest {
    path: String,
    response: oneshot::Sender<Vec<u8>>,
}

async fn controlled_server() -> (u16, mpsc::Receiver<ControlledRequest>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (requests_tx, requests_rx) = mpsc::channel(4);
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_server = count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let requests_tx = requests_tx.clone();
            let count = count_for_server.clone();
            tokio::spawn(async move {
                let mut buffered = Vec::new();
                while let Some(path) = read_request(&mut stream, &mut buffered).await {
                    let (response, response_rx) = oneshot::channel();
                    count.fetch_add(1, Ordering::SeqCst);
                    if requests_tx
                        .send(ControlledRequest { path, response })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Ok(body) = response_rx.await else {
                        return;
                    };
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                        body.len()
                    );
                    if stream.write_all(headers.as_bytes()).await.is_err()
                        || stream.write_all(&body).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (port, requests_rx, count)
}

async fn read_request(
    stream: &mut tokio::net::TcpStream,
    buffered: &mut Vec<u8>,
) -> Option<String> {
    loop {
        if let Some(header_end) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&buffered[..header_end]).ok()?;
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            let request_len = header_end + content_length;
            while buffered.len() < request_len {
                let mut chunk = [0; 4096];
                let read = stream.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                buffered.extend_from_slice(&chunk[..read]);
            }
            let request = buffered.drain(..request_len).collect::<Vec<_>>();
            return std::str::from_utf8(&request)
                .ok()?
                .lines()
                .next()?
                .split_whitespace()
                .nth(1)
                .and_then(|target| target.split('?').next())
                .map(str::to_owned);
        }
        let mut chunk = [0; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}

fn json_response(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}

async fn next_controlled_request(
    requests: &mut mpsc::Receiver<ControlledRequest>,
) -> ControlledRequest {
    for _ in 0..10_000 {
        match requests.try_recv() {
            Ok(request) => return request,
            Err(mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                panic!("controlled server stopped before receiving a request")
            }
        }
    }
    panic!("controlled server did not receive the expected request");
}

fn page(next_token: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "models": [{"modelId": "safe-model"}],
        "defaultModel": {"modelId": "safe-model"},
        "nextToken": next_token,
    })
}

// A per-page timeout would allow the second 11-second response to outlive
// the 20 seconds already spent on page one. The command must stop at one
// shared 30-second deadline and never request page three.
#[tokio::test(start_paused = true)]
async fn discovery_deadline_covers_all_catalog_pages() {
    let (port, mut requests, request_count) = controlled_server().await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(port)).unwrap());
    let tokens = Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move { DiscoveryClient::new(net, tokens).discover().await });

    let first = next_controlled_request(&mut requests).await;
    assert_eq!(first.path, "/");
    tokio::time::advance(Duration::from_secs(20)).await;
    first
        .response
        .send(json_response(page(Some("page-2"))))
        .unwrap();
    let second = next_controlled_request(&mut requests).await;
    assert_eq!(second.path, "/");
    let _second_response = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(11)).await;
        let _ = second.response.send(json_response(page(Some("page-3"))));
    });
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(
        !task.is_finished(),
        "discovery ended before its 30-second deadline"
    );
    tokio::time::advance(Duration::from_secs(1)).await;

    assert!(matches!(
        task.await.unwrap(),
        Err(DiscoveryError::LimitExceeded)
    ));
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(30)
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
}

// Refresh is part of the same operation. Giving it a separate 30-second
// allowance would allow the first catalog request to begin after 30 seconds.
#[tokio::test(start_paused = true)]
async fn discovery_deadline_includes_oidc_refresh_before_catalog() {
    let (port, mut requests, request_count) = controlled_server().await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(port)).unwrap());
    let tokens = Arc::new(TokenSource::new(
        make_db(dir.path(), "2020-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move { DiscoveryClient::new(net, tokens).discover().await });

    let refresh = next_controlled_request(&mut requests).await;
    assert_eq!(refresh.path, "/token");
    tokio::time::advance(Duration::from_secs(20)).await;
    refresh
        .response
        .send(json_response(serde_json::json!({
            "accessToken": "rotated-access",
            "refreshToken": "rotated-refresh",
            "expiresIn": 3600,
        })))
        .unwrap();
    let catalog = next_controlled_request(&mut requests).await;
    assert_eq!(catalog.path, "/");
    let _catalog_response = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(11)).await;
        let _ = catalog.response.send(json_response(page(Some("page-2"))));
    });
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(
        !task.is_finished(),
        "discovery ended before its 30-second deadline"
    );
    tokio::time::advance(Duration::from_secs(1)).await;

    assert!(matches!(
        task.await.unwrap(),
        Err(DiscoveryError::LimitExceeded)
    ));
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(30)
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
}

// A missing query/body duplication would send profile scope differently than
// the shipped CLI and fail this fixed-operation boundary test.
#[tokio::test]
async fn discovery_duplicates_typed_inputs_in_query_and_body() {
    let server = MockServer::start().await;
    let profile = "arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE";
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("origin", "CLI"))
        .and(query_param("profileArn", profile))
        .and(header(
            "x-amz-target",
            "AmazonCodeWhispererService.ListAvailableModels",
        ))
        .and(header("content-type", "application/x-amz-json-1.0"))
        .and(header("authorization", "Bearer fixture-access"))
        .and(body_json(serde_json::json!({
            "origin": "CLI",
            "profileArn": profile
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "models": [{"modelId": "claude-sonnet-4.6"}],
            "defaultModel": {"modelId": "claude-sonnet-4.6"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = Client::new(Policy::loopback_plain_http(server.address().port())).unwrap();
    let destination = Destination::ModelCatalog {
        region: DiscoveryRegion::parse("us-east-1").unwrap(),
    };
    let response = client
        .post_model_discovery(
            &destination,
            ModelDiscoveryQuery {
                profile_arn: profile,
                next_token: None,
            },
            SensitiveBearer::new("fixture-access").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
}

// A pagination loop that accepts a repeated token would make the foreground
// command unbounded. The second page must fail before a third request.
#[tokio::test]
async fn discovery_repeated_token_stops_before_a_third_request() {
    let server = MockServer::start().await;
    let page = serde_json::json!({
        "models": [{"modelId": "claude-sonnet-4.6"}],
        "defaultModel": {"modelId": "claude-sonnet-4.6"},
        "nextToken": "repeat"
    });
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = std::sync::Arc::new(
        Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
    );
    let tokens = std::sync::Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let error = DiscoveryClient::new(net, tokens)
        .discover()
        .await
        .unwrap_err();
    assert!(matches!(error, DiscoveryError::Protocol));
}

// If pagination constructed a fresh source, the second page would either use
// the stale bearer or repeat the refresh exchange. Both pages must reuse the
// ordinary source's rotated in-memory credential.
#[tokio::test]
async fn discovery_refreshes_expired_credential_and_uses_rotated_access_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_json(serde_json::json!({
            "grantType": "refresh_token",
            "clientId": "fixture-client",
            "clientSecret": "fixture-secret",
            "refreshToken": "fixture-refresh",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "rotated-access",
            "refreshToken": "rotated-refresh",
            "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("authorization", "Bearer rotated-access"))
        .respond_with(Sequence(std::sync::Mutex::new(vec![
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [{"modelId": "claude-sonnet-4.6"}],
                "defaultModel": {"modelId": "claude-sonnet-4.6"},
                "nextToken": "page-2"
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [{"modelId": "claude-sonnet-4.6"}],
                "defaultModel": {"modelId": "claude-sonnet-4.6"}
            })),
        ])))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = std::sync::Arc::new(
        Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
    );
    let tokens = std::sync::Arc::new(TokenSource::new(
        make_db(dir.path(), "2020-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let report = DiscoveryClient::new(net, tokens).discover().await.unwrap();
    assert_eq!(report.models.len(), 1);
}

// A catalog 403 can describe profile entitlement. It must end the command,
// not force the runtime-only invalidation and retry policy.
#[tokio::test]
async fn catalog_403_does_not_trigger_an_auth_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = std::sync::Arc::new(
        Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
    );
    let tokens = std::sync::Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let error = DiscoveryClient::new(net, tokens)
        .discover()
        .await
        .unwrap_err();
    assert!(matches!(error, DiscoveryError::AccessDenied));
}

#[tokio::test]
async fn expired_catalog_403_refreshes_once_and_catalog_401_is_fixed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"accessToken":"rotated","expiresIn":3600})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("authorization", "Bearer rotated"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = std::sync::Arc::new(
        Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
    );
    let tokens = std::sync::Arc::new(TokenSource::new(
        make_db(dir.path(), "2020-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    assert!(matches!(
        DiscoveryClient::new(net, tokens).discover().await,
        Err(DiscoveryError::AccessDenied)
    ));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = std::sync::Arc::new(
        Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
    );
    let tokens = std::sync::Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let error = DiscoveryClient::new(net, tokens)
        .discover()
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "authentication failed");
    assert!(matches!(error, DiscoveryError::Authentication));
}

#[tokio::test]
async fn discovery_model_limit_accepts_512_and_rejects_513() {
    for count in [512usize, 513] {
        let models: Vec<_> = (0..count)
            .map(|n| serde_json::json!({"modelId": format!("model-{n}")}))
            .collect();
        let result = discover_with_page(
            serde_json::json!({"models": models, "defaultModel": {"modelId": "model-0"}}),
        )
        .await;
        if count == 512 {
            assert_eq!(result.unwrap().models.len(), 512);
        } else {
            assert!(matches!(result, Err(DiscoveryError::LimitExceeded)));
        }
    }
}

#[tokio::test]
async fn discovery_page_limit_accepts_16_and_rejects_a_seventeenth_page() {
    for overflow in [false, true] {
        let server = MockServer::start().await;
        let mut pages = Vec::new();
        for page in 0..16 {
            let next = if page < 15 || overflow {
                Some(format!("p-{page}"))
            } else {
                None
            };
            pages.push(ResponseTemplate::new(200).set_body_json(serde_json::json!({"models":[{"modelId":"safe-model"}],"defaultModel":{"modelId":"safe-model"},"nextToken":next})));
        }
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(Sequence(std::sync::Mutex::new(pages)))
            .expect(16)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let net = std::sync::Arc::new(
            Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
        );
        let tokens = std::sync::Arc::new(TokenSource::new(
            make_db(dir.path(), "2099-01-01T00:00:00Z"),
            net.clone(),
            None,
        ));
        let result = DiscoveryClient::new(net, tokens).discover().await;
        if overflow {
            assert!(matches!(result, Err(DiscoveryError::LimitExceeded)));
        } else {
            assert_eq!(result.unwrap().page_count, 16);
        }
    }
}

#[tokio::test]
async fn discovery_body_limit_is_exact() {
    for (size, want_limit) in [(1_048_576usize, false), (1_048_577, true)] {
        let server = MockServer::start().await;
        let mut body = b"{\"models\":[],\"defaultModel\":{\"modelId\":\"safe-model\"}}".to_vec();
        body.resize(size, b' ');
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(Policy::loopback_plain_http(server.address().port())).unwrap();
        let dest = Destination::ModelCatalog {
            region: DiscoveryRegion::parse("us-east-1").unwrap(),
        };
        let result = client
            .post_model_discovery(
                &dest,
                ModelDiscoveryQuery {
                    profile_arn: "fixture",
                    next_token: None,
                },
                SensitiveBearer::new("fixture-access").unwrap(),
            )
            .await
            .unwrap()
            .model_catalog_bytes()
            .await;
        if want_limit {
            assert!(matches!(
                result,
                Err(kiro_trust_net::NetError::ModelCatalogBodyLimit)
            ));
        } else {
            assert_eq!(result.unwrap().len(), size);
        }
    }
}

#[tokio::test]
async fn discovery_duplicates_collapse_and_conflicts_fail() {
    for conflict in [false, true] {
        let server = MockServer::start().await;
        let first = serde_json::json!({"models":[{"modelId":"safe-model","tokenLimits":{"maxInputTokens":1}}],"defaultModel":{"modelId":"safe-model"},"nextToken":"p2"});
        let second = serde_json::json!({"models":[{"modelId":"safe-model","tokenLimits":{"maxInputTokens":if conflict {2} else {1}}}],"defaultModel":{"modelId":"safe-model"}});
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(Sequence(std::sync::Mutex::new(vec![
                ResponseTemplate::new(200).set_body_json(first),
                ResponseTemplate::new(200).set_body_json(second),
            ])))
            .expect(2)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let net = std::sync::Arc::new(
            Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
        );
        let tokens = std::sync::Arc::new(TokenSource::new(
            make_db(dir.path(), "2099-01-01T00:00:00Z"),
            net.clone(),
            None,
        ));
        let result = DiscoveryClient::new(net, tokens).discover().await;
        if conflict {
            assert!(matches!(result, Err(DiscoveryError::Protocol)));
        } else {
            assert_eq!(result.unwrap().models.len(), 1);
        }
    }
}

#[tokio::test]
async fn discovery_conflicting_page_defaults_fail() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(Sequence(Mutex::new(vec![
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [{"modelId": "safe-model"}, {"modelId": "other-model"}],
                "defaultModel": {"modelId": "safe-model"},
                "nextToken": "page-2",
            })),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [{"modelId": "safe-model"}, {"modelId": "other-model"}],
                "defaultModel": {"modelId": "other-model"},
            })),
        ])))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    let tokens = Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    assert!(matches!(
        DiscoveryClient::new(net, tokens).discover().await,
        Err(DiscoveryError::Protocol)
    ));
}

#[tokio::test]
async fn discovery_rejects_missing_or_unverified_profile_region_before_catalog() {
    for profile in [
        None,
        Some("arn:aws:codewhisperer:us-gov-west-1:000000000000:profile/FIXTURE"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let net =
            Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
        let tokens = Arc::new(TokenSource::new(
            make_db_with_profile(dir.path(), "2099-01-01T00:00:00Z", profile),
            net.clone(),
            None,
        ));
        let error = DiscoveryClient::new(net, tokens)
            .discover()
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "catalog region is unverified; source-verified regions: us-east-1, eu-central-1"
        );
        assert!(matches!(error, DiscoveryError::RegionUnverified));
    }
}

#[tokio::test]
async fn discovery_authentication_errors_are_fixed_and_do_not_reach_catalog() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let tokens = Arc::new(TokenSource::new(
        dir.path().join("missing.sqlite3"),
        net.clone(),
        None,
    ));
    let error = DiscoveryClient::new(net, tokens)
        .discover()
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "authentication failed");

    for response in [
        ResponseTemplate::new(400).set_body_string("REMOTE_OIDC_REJECTION fixture-access"),
        ResponseTemplate::new(200).set_body_string("REMOTE_INVALID_OIDC_RESPONSE fixture-access"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let net =
            Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
        let tokens = Arc::new(TokenSource::new(
            make_db(dir.path(), "2020-01-01T00:00:00Z"),
            net.clone(),
            None,
        ));
        let error = DiscoveryClient::new(net, tokens)
            .discover()
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "authentication failed");
        assert!(!error.to_string().contains("REMOTE_"));
    }
}

#[tokio::test]
async fn discovery_next_token_limit_and_percent_encoding() {
    for token in ["x".repeat(4096), "a+/=?#& %".to_string()] {
        let server = MockServer::start().await;
        let requests = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(RecordingSequence {
                requests: requests.clone(),
                responses: Mutex::new(vec![
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "models": [{"modelId": "safe-model"}],
                        "defaultModel": {"modelId": "safe-model"},
                        "nextToken": token,
                    })),
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "models": [{"modelId": "safe-model"}],
                        "defaultModel": {"modelId": "safe-model"},
                    })),
                ]),
            })
            .expect(2)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let net =
            Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
        let tokens = Arc::new(TokenSource::new(
            make_db(dir.path(), "2099-01-01T00:00:00Z"),
            net.clone(),
            None,
        ));
        let report = DiscoveryClient::new(net, tokens).discover().await.unwrap();
        assert_eq!(report.page_count, 2);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[1]
                .url
                .query_pairs()
                .any(|(name, value)| name == "nextToken" && value == token)
        );
        let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(body["nextToken"], token);
        for request in requests.iter() {
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                "Bearer fixture-access"
            );
            assert!(!request.url.as_str().contains("fixture-access"));
            assert!(!String::from_utf8_lossy(&request.body).contains("fixture-access"));
        }
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "models": [{"modelId": "safe-model"}],
            "defaultModel": {"modelId": "safe-model"},
            "nextToken": "x".repeat(4097),
        })))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    let tokens = Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let error = DiscoveryClient::new(net, tokens)
        .discover()
        .await
        .unwrap_err();
    assert!(matches!(error, DiscoveryError::LimitExceeded));
}

// A remote id one byte beyond the advertised bound is a fixed operation
// limit, not a malformed protocol shape.
#[tokio::test]
async fn discovery_id_limit_reports_limit_exceeded() {
    let server = MockServer::start().await;
    let id = "m".repeat(257);
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "models": [{"modelId": id}],
            "defaultModel": {"modelId": "valid-model"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = std::sync::Arc::new(
        Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
    );
    let tokens = std::sync::Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    let error = DiscoveryClient::new(net, tokens)
        .discover()
        .await
        .unwrap_err();
    assert!(matches!(error, DiscoveryError::LimitExceeded));

    let error = discover_with_page(serde_json::json!({
        "models": [{"modelId": "safe-model"}],
        "defaultModel": {"modelId": "m".repeat(257)},
    }))
    .await
    .unwrap_err();
    assert!(matches!(error, DiscoveryError::LimitExceeded));
}

#[tokio::test]
async fn discovery_id_limit_accepts_256_bytes() {
    let id = "m".repeat(256);
    let report = discover_with_page(serde_json::json!({
        "models": [{"modelId": id}],
        "defaultModel": {"modelId": "m".repeat(256)},
    }))
    .await
    .unwrap();
    assert_eq!(report.models[0].id.len(), 256);
}

async fn discover_with_page(
    page: serde_json::Value,
) -> Result<kiro_trust_kiro::DiscoveryReport, DiscoveryError> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = std::sync::Arc::new(
        Client::new(Policy::loopback_plain_http(server.address().port())).unwrap(),
    );
    let tokens = std::sync::Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    DiscoveryClient::new(net, tokens).discover().await
}

async fn discover_with_raw_page(
    page: &str,
) -> Result<kiro_trust_kiro::DiscoveryReport, DiscoveryError> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(page, "application/json"))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    let tokens = Arc::new(TokenSource::new(
        make_db(dir.path(), "2099-01-01T00:00:00Z"),
        net.clone(),
        None,
    ));
    DiscoveryClient::new(net, tokens).discover().await
}

#[tokio::test]
async fn discovery_token_limits_and_input_types_are_bounded_and_sanitized() {
    let report = discover_with_page(serde_json::json!({
        "models": [{
            "modelId": "safe-model",
            "tokenLimits": {"maxInputTokens": 1, "maxOutputTokens": 4294967295u64},
            "supportedInputTypes": ["OTHER_REMOTE_LITERAL", "IMAGE", "TEXT", "TEXT"],
            "supportsPromptCache": true
        }],
        "defaultModel": {"modelId": "safe-model"}
    }))
    .await
    .unwrap();
    assert_eq!(report.models[0].max_input_tokens, Some(1));
    assert_eq!(report.models[0].max_output_tokens, Some(u32::MAX));
    assert_eq!(
        serde_json::to_value(&report.models[0].input_types).unwrap(),
        serde_json::json!(["text", "image", "unknown"])
    );
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("OTHER_REMOTE_LITERAL"));
    for invalid in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(4294967296u64),
    ] {
        let error = discover_with_page(serde_json::json!({
            "models": [{"modelId": "safe-model", "tokenLimits": {"maxInputTokens": invalid}}],
            "defaultModel": {"modelId": "safe-model"}
        }))
        .await
        .unwrap_err();
        assert!(matches!(error, DiscoveryError::Protocol));
    }

    for page in [
        serde_json::json!({
            "models": [{"modelId": "safe-model", "tokenLimits": null, "rateMultiplier": null}],
            "defaultModel": {"modelId": "safe-model"},
        }),
        serde_json::json!({
            "models": [{"modelId": "safe-model"}],
            "defaultModel": {"modelId": "safe-model"},
        }),
    ] {
        let report = discover_with_page(page).await.unwrap();
        assert_eq!(report.models[0].max_input_tokens, None);
        assert_eq!(report.models[0].max_output_tokens, None);
        assert_eq!(report.models[0].rate_multiplier, None);
    }

    let negative = discover_with_page(serde_json::json!({
        "models": [{"modelId": "safe-model", "rateMultiplier": -0.1}],
        "defaultModel": {"modelId": "safe-model"},
    }))
    .await
    .unwrap_err();
    assert!(matches!(negative, DiscoveryError::Protocol));
    for raw in [
        r#"{"models":[{"modelId":"safe-model","rateMultiplier":NaN}],"defaultModel":{"modelId":"safe-model"}}"#,
        r#"{"models":[{"modelId":"safe-model","rateMultiplier":1e9999}],"defaultModel":{"modelId":"safe-model"}}"#,
    ] {
        let error = discover_with_raw_page(raw).await.unwrap_err();
        assert!(matches!(error, DiscoveryError::Protocol));
    }
}

#[tokio::test]
async fn discovery_rejects_default_and_sensitive_identifier_values() {
    for id in [
        "bad\nmodel",
        "bad\u{1b}model",
        "bad\u{0085}model",
        "arn:aws:bad",
        "123456789012",
        "aoa-secret",
        "eyJsecret",
    ] {
        let error = discover_with_page(serde_json::json!({
            "models": [
                {"modelId": "safe-model"},
                {"modelId": id},
            ],
            "defaultModel": {"modelId": "safe-model"},
        }))
        .await
        .unwrap_err();
        assert!(matches!(error, DiscoveryError::Protocol));
    }
    for page in [
        serde_json::json!({"models": [{"modelId": "bad\nmodel"}], "defaultModel": {"modelId": "safe-model"}}),
        serde_json::json!({"models": [{"modelId": "safe-model"}], "defaultModel": {"modelId": "bad\nmodel"}}),
        serde_json::json!({"models": [{"modelId": "safe-model"}]}),
        serde_json::json!({"models": [{"modelId": "safe-model"}], "defaultModel": {"modelId": "other"}}),
    ] {
        assert!(matches!(
            discover_with_page(page).await,
            Err(DiscoveryError::Protocol)
        ));
    }
}

#[tokio::test]
async fn discovery_renderers_emit_only_allowlisted_fields() {
    let report = discover_with_page(serde_json::json!({
        "models": [{
            "modelId": "safe-model",
            "displayName": "REMOTE_DISPLAY_NAME\u{001b}[2J",
            "description": "REMOTE_DESCRIPTION arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE",
            "rateMultiplier": 1.25,
            "rateUnit": "REMOTE_RATE_UNIT fixture-access-token",
            "supportedInputTypes": ["OTHER_REMOTE_LITERAL"],
            "unknownFreeForm": "eyJremote-token",
        }],
        "defaultModel": {"modelId": "safe-model"},
    }))
    .await
    .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let text = kiro_trust::models_cmd::render_discovery(&report);
    assert_eq!(
        json,
        r#"{"object":"discovered_models","region":"us-east-1","default_model":"safe-model","models":[{"id":"safe-model","available":true,"catalog_status":"not_listed","input_types":["unknown"],"max_input_tokens":null,"max_output_tokens":null,"supports_prompt_cache":null,"rate_multiplier":1.25}]}"#
    );
    assert_eq!(
        text,
        "AVAILABLE ID\tCATALOG STATUS\tINPUTS\tINPUT LIMIT\tOUTPUT LIMIT\tPROMPT CACHE\n\
safe-model\tnot_listed\tunknown\tnull\tnull\tnull\n"
    );
}

#[tokio::test]
async fn discovery_renderers_show_supported_and_not_listed_catalog_statuses() {
    let report = discover_with_page(serde_json::json!({
        "models": [
            {"modelId": "claude-sonnet-4.6"},
            {"modelId": "unlisted-model"}
        ],
        "defaultModel": {"modelId": "claude-sonnet-4.6"}
    }))
    .await
    .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let text = kiro_trust::models_cmd::render_discovery(&report);
    assert_eq!(
        json,
        r#"{"object":"discovered_models","region":"us-east-1","default_model":"claude-sonnet-4.6","models":[{"id":"claude-sonnet-4.6","available":true,"catalog_status":"supported","input_types":[],"max_input_tokens":null,"max_output_tokens":null,"supports_prompt_cache":null,"rate_multiplier":null},{"id":"unlisted-model","available":true,"catalog_status":"not_listed","input_types":[],"max_input_tokens":null,"max_output_tokens":null,"supports_prompt_cache":null,"rate_multiplier":null}]}"#
    );
    assert_eq!(
        text,
        "AVAILABLE ID\tCATALOG STATUS\tINPUTS\tINPUT LIMIT\tOUTPUT LIMIT\tPROMPT CACHE\n\
claude-sonnet-4.6\tsupported\t\tnull\tnull\tnull\n\
unlisted-model\tnot_listed\t\tnull\tnull\tnull\n"
    );
}

#[tokio::test]
async fn discovery_fixed_operation_rejects_wrong_destination_and_redirect() {
    let server = MockServer::start().await;
    let evil = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", evil.uri()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&evil)
        .await;
    let client = Client::new(Policy::loopback_plain_http(server.address().port())).unwrap();
    let catalog = Destination::ModelCatalog {
        region: DiscoveryRegion::parse("us-east-1").unwrap(),
    };
    let runtime = Destination::Runtime {
        region: kiro_trust_net::RuntimeRegion::parse("us-east-1").unwrap(),
    };
    assert!(matches!(
        client
            .post(&catalog, "/", http::HeaderMap::new(), vec![])
            .await,
        Err(kiro_trust_net::NetError::ModelCatalogOperation)
    ));
    assert!(matches!(
        client
            .post_model_discovery(
                &runtime,
                ModelDiscoveryQuery {
                    profile_arn: "fixture",
                    next_token: None
                },
                SensitiveBearer::new("fixture-access").unwrap()
            )
            .await,
        Err(kiro_trust_net::NetError::ModelCatalogDestination)
    ));
    assert!(matches!(
        client
            .post_model_discovery(
                &catalog,
                ModelDiscoveryQuery {
                    profile_arn: "fixture",
                    next_token: None
                },
                SensitiveBearer::new("fixture-access").unwrap()
            )
            .await,
        Err(kiro_trust_net::NetError::Redirect { status: 302 })
    ));
}

/// Live evidence for a source-verified region. It is ignored by default and
/// prints only aggregate counts and duration after a successful response.
#[tokio::test]
#[ignore]
async fn model_discovery_returns_bounded_metadata() {
    assert_eq!(std::env::var("KIRO_TRUST_LIVE").as_deref(), Ok("1"));
    let db = kiro_trust_auth::default_db_path().expect("normal Kiro CLI database path");
    let net = std::sync::Arc::new(Client::new(Policy::production()).unwrap());
    let tokens = std::sync::Arc::new(TokenSource::new(db, net.clone(), None));
    let started = std::time::Instant::now();
    let report = DiscoveryClient::new(net, tokens).discover().await.unwrap();
    assert!(!report.models.is_empty());
    assert!(
        report
            .models
            .iter()
            .any(|model| model.id == report.default_model)
    );
    let unique: std::collections::HashSet<_> =
        report.models.iter().map(|model| &model.id).collect();
    assert_eq!(unique.len(), report.models.len());
    println!(
        "pages={} models={} duration_ms={}",
        report.page_count,
        report.models.len(),
        started.elapsed().as_millis()
    );
}

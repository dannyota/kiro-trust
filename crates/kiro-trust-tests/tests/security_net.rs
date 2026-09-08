use http::HeaderMap;
use kiro_trust_net::{Client, Destination, NetError, Policy, RuntimeRegion};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn runtime() -> Destination {
    Destination::Runtime {
        region: RuntimeRegion::parse("us-east-1").unwrap(),
    }
}

// spec 6.2: a 3xx from either host fails without following.
#[tokio::test]
async fn runtime_redirect_rejected() {
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
    let err = client
        .post(&runtime(), "/", HeaderMap::new(), b"{}".to_vec())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::Redirect { status: 302 }));
    assert!(
        !format!("{err}").contains(&evil.uri()),
        "the Location target is never echoed"
    );
}

#[tokio::test]
async fn oidc_redirect_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(301).insert_header("location", "https://example.com/"))
        .expect(1)
        .mount(&server)
        .await;
    let client = Client::new(Policy::loopback_plain_http(server.address().port())).unwrap();
    let dest = Destination::Oidc {
        sso_region: kiro_trust_net::Region::parse("ap-southeast-1").unwrap(),
    };
    let err = client
        .post(&dest, "/token", HeaderMap::new(), b"{}".to_vec())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::Redirect { status: 301 }));
}

// spec 6.2: proxy environment variables are ignored.
#[tokio::test]
async fn proxy_env_ignored() {
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((_s, _)) = proxy.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    for var in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
    ] {
        // SAFETY: this test binary sets the variables before any other thread reads them.
        unsafe { std::env::set_var(var, format!("http://{proxy_addr}")) };
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;
    let client = Client::new(Policy::loopback_plain_http(server.address().port())).unwrap();
    let resp = client
        .post(&runtime(), "/", HeaderMap::new(), b"{}".to_vec())
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the proxy socket never saw a connection"
    );
}

#[tokio::test]
async fn error_bodies_are_capped() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_bytes(vec![b'x'; 200_000]))
        .mount(&server)
        .await;
    let mut policy = Policy::loopback_plain_http(server.address().port());
    policy.max_error_body = 1024;
    let client = Client::new(policy).unwrap();
    let resp = client
        .post(&runtime(), "/", HeaderMap::new(), vec![])
        .await
        .unwrap();
    assert_eq!(resp.status, 500);
    let body = resp.bytes_limited().await.unwrap();
    assert_eq!(body.len(), 1024);
}

// spec 3.2: a hostile path must never move the request (and its bearer
// token) to a different authority.
#[tokio::test]
async fn path_cannot_change_the_authority() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let client = Client::new(Policy::loopback_plain_http(server.address().port())).unwrap();
    for bad_path in ["@evil.com/", "//evil.com/", "x", "/token?x=1"] {
        let err = client
            .post(&runtime(), bad_path, HeaderMap::new(), b"{}".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::BadPath { .. }), "{bad_path}");
    }

    let ok_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&ok_server)
        .await;
    let ok_client = Client::new(Policy::loopback_plain_http(ok_server.address().port())).unwrap();
    let resp = ok_client
        .post(&runtime(), "/token", HeaderMap::new(), b"{}".to_vec())
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
}

#[test]
fn production_policy_is_https_only_with_no_override() {
    let p = Policy::production();
    assert!(p.https_only());
    assert_eq!(p.read_idle_timeout, Duration::from_secs(180));
    assert_eq!(p.connect_timeout, Duration::from_secs(10));
    assert_eq!(p.header_timeout, Duration::from_secs(30));
    assert_eq!(p.max_error_body, 64 * 1024);
}

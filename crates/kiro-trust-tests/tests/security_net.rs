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

// spec 6.2: the compiled webpki-roots are the only source of trust when no
// --extra-ca is configured; SSL_CERT_FILE and the system store are never
// read. `kiro-trust-net::Client::new` builds its TLS config from
// `rustls::ClientConfig::builder().with_root_certificates(...)` seeded only
// from `webpki_roots::TLS_SERVER_ROOTS` (plus, additively, an `ExtraCa` when
// one is configured) and hands that preconfigured config to reqwest via
// `tls_backend_preconfigured`, so no code path in this crate ever consults
// SSL_CERT_FILE or an OS trust store. This is a black-box proof from
// kiro-trust-tests, which cannot see kiro-trust-net's private root store: if
// SSL_CERT_FILE were read at all to build the client (the way OpenSSL or
// native-tls backends do), pointing it at a nonexistent, unreadable path
// would make `Client::new` fail; it does not, with or without the variable
// set, which is exactly what "environment ignored" (spec 6.2, audit's
// `HTTP_PROXY` line's sibling claim about the TLS roots line) means here.
#[test]
fn ssl_cert_file_is_ignored_when_building_the_default_client() {
    let bogus = "/nonexistent/definitely-not-a-cert-store.pem";
    // SAFETY: this test only ever reads its own effect on `Client::new`
    // below within this one function body; it restores the prior value
    // (or removes the variable) before returning either way.
    let previous = std::env::var("SSL_CERT_FILE").ok();
    unsafe { std::env::set_var("SSL_CERT_FILE", bogus) };

    let with_bogus_var = Client::new(Policy::production());

    match previous {
        Some(v) => unsafe { std::env::set_var("SSL_CERT_FILE", v) },
        None => unsafe { std::env::remove_var("SSL_CERT_FILE") },
    }

    assert!(
        with_bogus_var.is_ok(),
        "Client::new must not fail or change behavior based on SSL_CERT_FILE: {:?}",
        with_bogus_var.err()
    );
}

// spec 6.2: proxy environment variables stay ignored even when an extra CA
// is configured (the additive flag changes only the trust anchors, nothing
// about proxy or redirect handling). Complements `proxy_env_ignored` above,
// which covers the default policy with no extra CA.
#[tokio::test]
async fn proxy_env_ignored_with_an_extra_ca_configured() {
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((_s, _)) = proxy.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        // SAFETY: this test binary sets the variables before any other
        // thread reads them, matching `proxy_env_ignored` above.
        unsafe { std::env::set_var(var, format!("http://{proxy_addr}")) };
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;
    let extra_ca = kiro_trust_net::ExtraCa::from_pem(TEST_CA_PEM.as_bytes()).unwrap();
    let policy = Policy::loopback_plain_http(server.address().port()).with_extra_ca(extra_ca);
    let client = Client::new(policy).unwrap();
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
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        unsafe { std::env::remove_var(var) };
    }
}

/// The shared test CA fixture: one self-signed P-256 CA certificate, public
/// part only, no private key (spec 6.2 validates `--extra-ca` against real CA
/// material, not just PEM framing). `include_str!` rather than a copied
/// literal so the four call sites across three crates cannot drift apart, and
/// so a rename breaks the build instead of one test at a time. See
/// `tests/fixtures/ca/README.md`.
const TEST_CA_PEM: &str = include_str!("../../../tests/fixtures/ca/test-ca.crt");

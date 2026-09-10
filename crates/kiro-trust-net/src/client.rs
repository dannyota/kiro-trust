//! The one HTTP client: rustls with compiled-in roots, HTTPS only, no
//! redirects, no proxy, bounded timeouts (spec 3.2, 6.2).

use crate::destination::Destination;
use crate::policy::{ExtraCaError, Policy};
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt, TryStreamExt};
use http::HeaderMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const HEALTH_PROBE_MAX_BODY: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("client build failed: {0}")]
    Build(String),
    #[error("transport error to {host}: {detail}")]
    Transport { host: String, detail: String },
    #[error("upstream answered {status} redirect; redirects are rejected")]
    Redirect { status: u16 },
    #[error("no response headers within {0:?}")]
    HeaderTimeout(Duration),
    #[error("body read failed: {0}")]
    Body(String),
    #[error(
        "request path would change the authority for {host}; paths must be absolute and carry no userinfo"
    )]
    BadPath { host: String },
    /// An `--extra-ca` PEM failed to parse or contained no usable trust
    /// anchor (spec 6.2). Deliberately carries only the fixed reason class
    /// from `ExtraCaError`: never a file path (the caller that read the file
    /// attaches that itself) and never certificate bytes.
    #[error("extra CA rejected: {0}")]
    ExtraCa(ExtraCaError),
    #[error("loopback health probe failed")]
    HealthProbe,
}

/// Sends the only plaintext request permitted in production: a fixed,
/// unauthenticated HTTP/1 health request to a loopback socket. The caller
/// supplies a `SocketAddr`, never a URL, host, path, method, or header.
pub async fn probe_loopback_health(addr: SocketAddr) -> Result<(), NetError> {
    if !addr.ip().is_loopback() {
        return Err(NetError::HealthProbe);
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .http1_only()
        .connect_timeout(HEALTH_PROBE_TIMEOUT)
        .build()
        .map_err(|_| NetError::HealthProbe)?;
    let url = format!("http://{addr}/health");
    let response = client
        .get(url)
        .timeout(HEALTH_PROBE_TIMEOUT)
        .send()
        .await
        .map_err(|_| NetError::HealthProbe)?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            != Some("application/json")
    {
        return Err(NetError::HealthProbe);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| NetError::HealthProbe)?;
        if body.len().saturating_add(chunk.len()) > HEALTH_PROBE_MAX_BODY {
            return Err(NetError::HealthProbe);
        }
        body.extend_from_slice(&chunk);
    }
    if body == br#"{"status":"ok"}"# {
        Ok(())
    } else {
        Err(NetError::HealthProbe)
    }
}

/// Root store `kiro-trust audit` reports (spec 6.6): kept next to the
/// `with_root_certificates` call in `Client::new` below so changing the
/// compiled-in root store without updating this text is visibly wrong to a
/// reader (task-20-fix-1.md Important 2).
pub const TLS_ROOTS: &str = "webpki-roots (compiled in)";
/// Proxy behavior `kiro-trust audit` reports: kept next to the
/// `.no_proxy()` call below (task-20-fix-1.md Important 2).
pub const HTTP_PROXY: &str = "disabled (environment ignored)";
/// Redirect behavior `kiro-trust audit` reports: kept next to the
/// `.redirect(...)` call below (task-20-fix-1.md Important 2).
pub const REDIRECTS: &str = "rejected";

pub struct Client {
    inner: reqwest::Client,
    policy: Policy,
    /// Test-only: how many trust anchors `new` built the TLS config with, so
    /// a test can prove the real constructor honored the policy's extra CA
    /// rather than only proving `build_roots` would have. Never read in
    /// production code and never exposed outside this crate.
    #[cfg(test)]
    configured_root_count: usize,
}

impl Client {
    pub fn new(policy: Policy) -> Result<Self, NetError> {
        let roots = Self::build_roots(&policy);
        #[cfg(test)]
        let configured_root_count = roots.roots.len();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let inner = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(reqwest::redirect::Policy::none()) // audit reports this as REDIRECTS
            .no_proxy() // audit reports this as HTTP_PROXY
            .https_only(policy.https_only())
            .http1_only()
            .connect_timeout(policy.connect_timeout)
            .read_timeout(policy.read_idle_timeout)
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|e| NetError::Build(e.without_url().to_string()))?;
        Ok(Client {
            inner,
            policy,
            #[cfg(test)]
            configured_root_count,
        })
    }

    /// Builds the root store this client's TLS config trusts: the compiled
    /// `webpki-roots` set first, then, additively, every certificate from
    /// `policy`'s `ExtraCa` if one is set (spec 6.2). Never the reverse
    /// order and never a replacement: an extra CA can only add anchors.
    fn build_roots(policy: &Policy) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty(); // audit reports this root store as TLS_ROOTS
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(extra_ca) = policy.extra_ca() {
            extra_ca.add_to(&mut roots);
        }
        roots
    }

    /// Test-only: proves the compiled `webpki-roots` set survives when an
    /// extra CA is configured, without exposing root contents to any
    /// consumer (brief: "the compiled webpki-roots must remain present when
    /// an extra CA is configured").
    #[cfg(test)]
    fn root_count(policy: &Policy) -> usize {
        Self::build_roots(policy).roots.len()
    }

    /// Test-only: the number of trust anchors this client's *own* TLS config
    /// was built with, recorded at construction.
    ///
    /// This exists because every other test in this module can only reach
    /// `build_roots`, directly or through a helper that assembles its own
    /// `ClientConfig`. That left the one line in `Client::new` that consumes
    /// `build_roots` untested: replacing `Client::new`'s body with the
    /// pre-`ExtraCa` form, which ignores `policy.extra_ca()` entirely, kept
    /// every test green while the shipped client silently stopped honoring
    /// `--extra-ca` (v020-net-review.md, finding 2). Recording the count the
    /// real constructor actually used closes that gap: a `Client::new` that
    /// stops routing through `build_roots` fails
    /// `client_new_uses_the_extra_ca_from_its_policy` below.
    #[cfg(test)]
    fn configured_root_count(&self) -> usize {
        self.configured_root_count
    }

    fn url(&self, dest: &Destination, path: &str) -> String {
        match self.policy.loopback_port() {
            Some(port) => format!("http://127.0.0.1:{port}{path}"),
            None => format!("https://{}{path}", dest.host()),
        }
    }

    /// Builds the request URL and proves it still names exactly the
    /// destination host: a hostile `path` must never be able to move the
    /// bearer token to a different authority (spec 3.2, 6.2).
    fn checked_url(&self, dest: &Destination, path: &str) -> Result<reqwest::Url, NetError> {
        let host = dest.host();
        let bad = || NetError::BadPath { host: host.clone() };
        // Reject up front so the failure is explicit rather than dependent
        // on parser behavior: an absolute path only, no userinfo
        // separator, no query or fragment, no backslash (some HTTP stacks
        // normalize it to a slash), and no leading "//" (a network-path
        // reference some URL resolvers treat as authority-carrying).
        if !path.starts_with('/') || path.starts_with("//") || path.contains(['@', '?', '#', '\\'])
        {
            return Err(bad());
        }
        let url = reqwest::Url::parse(&self.url(dest, path)).map_err(|_| bad())?;
        let (expected_host, expected_port) = match self.policy.loopback_port() {
            Some(port) => ("127.0.0.1".to_string(), port),
            None => (host.clone(), 443),
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || url.host_str() != Some(expected_host.as_str())
            || url.port_or_known_default() != Some(expected_port)
        {
            return Err(bad());
        }
        Ok(url)
    }

    pub async fn post(
        &self,
        dest: &Destination,
        path: &str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<Response, NetError> {
        let host = dest.host();
        let url = self.checked_url(dest, path)?;
        let send = self.inner.post(url).headers(headers).body(body).send();
        let resp = match tokio::time::timeout(self.policy.header_timeout, send).await {
            Err(_) => return Err(NetError::HeaderTimeout(self.policy.header_timeout)),
            Ok(Err(e)) => {
                return Err(NetError::Transport {
                    host,
                    detail: e.without_url().to_string(),
                });
            }
            Ok(Ok(r)) => r,
        };
        let status = resp.status();
        if status.is_redirection() {
            return Err(NetError::Redirect {
                status: status.as_u16(),
            });
        }
        Ok(Response {
            status: status.as_u16(),
            headers: resp.headers().clone(),
            inner: resp,
            max_error_body: self.policy.max_error_body,
        })
    }

    /// Test-only: completes a TLS handshake against an arbitrary loopback
    /// address, trusting exactly the root store `policy` would give a real
    /// `Client` (spec 6.2's `--extra-ca`). `Destination` only ever names the
    /// two production hosts, so this is the one sanctioned way for this
    /// crate's own tests to prove root-store behavior against a test TLS
    /// server. Gated on `cfg(test)` alone, not the `test-endpoints`
    /// feature: it calls `tokio-rustls`, a dev-dependency, so this must stay
    /// out of every non-test build, including one that unifies
    /// `test-endpoints` in from `kiro-trust-tests` (AGENTS.md Architecture
    /// rules) without also running `cargo test`.
    #[cfg(test)]
    async fn test_tls_connect(
        policy: &Policy,
        addr: std::net::SocketAddr,
        server_name: &str,
    ) -> Result<(), NetError> {
        let roots = Self::build_roots(policy);
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls));
        let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|_| NetError::Build("invalid test server name".to_string()))?;
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| NetError::Transport {
                host: addr.to_string(),
                detail: e.to_string(),
            })?;
        connector
            .connect(domain, tcp)
            .await
            .map_err(|e| NetError::Transport {
                host: addr.to_string(),
                detail: e.to_string(),
            })?;
        Ok(())
    }
}

pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    inner: reqwest::Response,
    max_error_body: usize,
}

// Manual, not derived: header values and the body are never part of the
// Debug output, matching the rule that error and response formatting never
// leaks a header value or body (spec 6.4).
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Response {
    pub fn content_type(&self) -> Option<String> {
        self.headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    /// Read at most `max_error_body` bytes and drop the rest.
    pub async fn bytes_limited(self) -> Result<Vec<u8>, NetError> {
        let max = self.max_error_body;
        let mut out = Vec::new();
        let mut stream = self.inner.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| NetError::Body(e.without_url().to_string()))?;
            let room = max - out.len();
            if chunk.len() >= room {
                out.extend_from_slice(&chunk[..room]);
                break;
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    pub fn into_stream(self) -> BoxStream<'static, Result<Bytes, NetError>> {
        self.inner
            .bytes_stream()
            .map_err(|e| NetError::Body(e.without_url().to_string()))
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ExtraCa;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use tokio::net::TcpListener;

    /// A self-signed CA and a "localhost" leaf certificate it signed, for
    /// proving the default policy rejects a server this CA vouches for while
    /// a policy carrying the CA connects (brief: prove `ExtraCa` actually
    /// changes what TLS trusts, not just that it parses).
    struct TestPki {
        ca_pem: String,
        leaf_cert_der: rustls::pki_types::CertificateDer<'static>,
        leaf_key_der: rustls::pki_types::PrivateKeyDer<'static>,
    }

    fn build_test_pki() -> TestPki {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        TestPki {
            ca_pem,
            leaf_cert_der: leaf_cert.der().clone(),
            leaf_key_der: leaf_key.into(),
        }
    }

    /// Serves one TLS connection on loopback with the given leaf certificate
    /// and key, then stops. Returns the bound port.
    async fn serve_one_tls_connection(
        cert: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                // The handshake is all this test needs; a client that
                // rejects the certificate never gets this far, and a
                // client that accepts it completes here. Either way the
                // server has nothing further to do.
                let _ = acceptor.accept(tcp).await;
            }
        });
        port
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn default_policy_rejects_server_signed_by_unknown_ca() {
        let pki = build_test_pki();
        let port = serve_one_tls_connection(pki.leaf_cert_der, pki.leaf_key_der).await;
        let policy = Policy::production();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let result = Client::test_tls_connect(&policy, addr, "localhost").await;
        assert!(
            result.is_err(),
            "default compiled roots must not trust a test-only CA"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn policy_with_extra_ca_connects_to_server_signed_by_that_ca() {
        let pki = build_test_pki();
        let port = serve_one_tls_connection(pki.leaf_cert_der, pki.leaf_key_der).await;
        let extra_ca = ExtraCa::from_pem(pki.ca_pem.as_bytes()).unwrap();
        let policy = Policy::production().with_extra_ca(extra_ca);
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let result = Client::test_tls_connect(&policy, addr, "localhost").await;
        assert!(
            result.is_ok(),
            "a policy carrying the signing CA must connect: {:?}",
            result.err()
        );
    }

    /// The regression test for v020-net-review.md finding 2: it fails if
    /// `Client::new` stops routing through `build_roots`, which is the edit
    /// that silently disabled `--extra-ca` while all 15 other tests stayed
    /// green. Asserts on the real constructor, not on a helper's own
    /// `ClientConfig`.
    #[test]
    fn client_new_uses_the_extra_ca_from_its_policy() {
        let compiled = webpki_roots::TLS_SERVER_ROOTS.len();

        let plain = Client::new(Policy::production()).unwrap();
        assert_eq!(
            plain.configured_root_count(),
            compiled,
            "a client with no extra CA must be built with exactly the compiled roots"
        );

        let extra_ca = {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let pem = params.self_signed(&key).unwrap().pem();
            ExtraCa::from_pem(pem.as_bytes()).unwrap()
        };
        let with_ca = Client::new(Policy::production().with_extra_ca(extra_ca)).unwrap();
        assert_eq!(
            with_ca.configured_root_count(),
            compiled + 1,
            "the real constructor must add the policy's extra CA to the compiled roots"
        );
    }

    #[test]
    fn compiled_roots_are_present_with_no_extra_ca() {
        let policy = Policy::production();
        let count = Client::root_count(&policy);
        assert_eq!(count, webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn compiled_roots_survive_when_an_extra_ca_is_configured() {
        let extra_ca = {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let pem = params.self_signed(&key).unwrap().pem();
            ExtraCa::from_pem(pem.as_bytes()).unwrap()
        };
        let compiled_count = webpki_roots::TLS_SERVER_ROOTS.len();
        let policy = Policy::production().with_extra_ca(extra_ca);
        let count = Client::root_count(&policy);
        // Additive only (spec 6.2): the compiled set must still be all
        // present, plus exactly the one extra root, never fewer than the
        // compiled count and never a replacement of it.
        assert_eq!(count, compiled_count + 1);
    }
}

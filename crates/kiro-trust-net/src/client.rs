//! The one HTTP client: rustls with compiled-in roots, HTTPS only, no
//! redirects, no proxy, bounded timeouts (spec 3.2, 6.2).

use crate::destination::Destination;
use crate::policy::Policy;
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt, TryStreamExt};
use http::HeaderMap;
use std::fmt;
use std::time::Duration;

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
}

pub struct Client {
    inner: reqwest::Client,
    policy: Policy,
}

impl Client {
    pub fn new(policy: Policy) -> Result<Self, NetError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let inner = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(policy.https_only())
            .http1_only()
            .connect_timeout(policy.connect_timeout)
            .read_timeout(policy.read_idle_timeout)
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|e| NetError::Build(e.without_url().to_string()))?;
        Ok(Client { inner, policy })
    }

    fn url(&self, dest: &Destination, path: &str) -> String {
        match self.policy.loopback_port() {
            Some(port) => format!("http://127.0.0.1:{port}{path}"),
            None => format!("https://{}{path}", dest.host()),
        }
    }

    pub async fn post(
        &self,
        dest: &Destination,
        path: &str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<Response, NetError> {
        let host = dest.host();
        let send = self
            .inner
            .post(self.url(dest, path))
            .headers(headers)
            .body(body)
            .send();
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

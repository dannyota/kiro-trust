//! The Kiro runtime client (spec 3.4). Transcribed from kirocc
//! internal/kiroclient/client.go and backoff.go.

use crate::error::{
    UpstreamError, UpstreamErrorKind, is_event_stream_content_type, is_retryable_exception,
    parse_exception_message, parse_exception_type,
};
use crate::headers::{AMZ_TARGET, AMZ_USER_AGENT, CONTENT_TYPE, MAX_ATTEMPTS, USER_AGENT};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt, TryStreamExt};
use http::{HeaderMap, HeaderValue, header};
use kiro_trust_auth::{AuthError, TokenSource};
use kiro_trust_net::{Client, Destination, NetError};
use kiro_trust_protocol::kiro::Payload;
use std::sync::Arc;
use std::time::Duration;

pub struct UpstreamStream {
    pub attempts: u32,
    pub bytes: BoxStream<'static, Result<Bytes, UpstreamError>>,
}

// Manual, not derived: `bytes` has no `Debug` impl, and `Result::unwrap_err`
// requires the `Ok` side to be `Debug`. Body content is never included.
impl std::fmt::Debug for UpstreamStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamStream")
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait Upstream: Send + Sync {
    async fn generate(&self, payload: &Payload) -> Result<UpstreamStream, UpstreamError>;
}

pub struct KiroClient {
    net: Arc<Client>,
    tokens: Arc<TokenSource>,
    share_content: bool,
    base_delay: Duration,
}

impl KiroClient {
    pub fn new(net: Arc<Client>, tokens: Arc<TokenSource>, share_content: bool) -> Self {
        KiroClient {
            net,
            tokens,
            share_content,
            base_delay: Duration::from_secs(1),
        }
    }

    pub fn with_base_delay(mut self, d: Duration) -> Self {
        self.base_delay = d;
        self
    }

    /// Exponential with ±25% jitter: 1 s, 2 s (kirocc backoffDelay).
    fn backoff(&self, attempt: u32) -> Duration {
        let base = self.base_delay * 2u32.pow(attempt.saturating_sub(1));
        let jitter = base.as_secs_f64() * rand::random_range(-0.25..=0.25);
        Duration::from_secs_f64((base.as_secs_f64() + jitter).max(0.0))
    }

    async fn headers(&self, attempt: u32, invocation_id: &str) -> Result<HeaderMap, UpstreamError> {
        let auth = self
            .tokens
            .with_token(|t| HeaderValue::from_str(&format!("Bearer {t}")))
            .await
            .map_err(auth_error)?
            .map_err(|_| {
                UpstreamError::new(
                    UpstreamErrorKind::Auth,
                    None,
                    None,
                    "token is not a valid header value",
                )
            })?;
        let mut auth = auth;
        auth.set_sensitive(true);
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, auth);
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
        h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        h.insert("x-amz-target", HeaderValue::from_static(AMZ_TARGET));
        h.insert(header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
        h.insert("x-amz-user-agent", HeaderValue::from_static(AMZ_USER_AGENT));
        h.insert(
            "x-amzn-codewhisperer-optout",
            HeaderValue::from_static(if self.share_content { "false" } else { "true" }),
        );
        h.insert(
            "amz-sdk-invocation-id",
            HeaderValue::from_str(invocation_id).unwrap(),
        );
        h.insert(
            "amz-sdk-request",
            HeaderValue::from_str(&format!("attempt={attempt}; max={MAX_ATTEMPTS}")).unwrap(),
        );
        Ok(h)
    }
}

fn auth_error(e: AuthError) -> UpstreamError {
    UpstreamError::new(UpstreamErrorKind::Auth, None, None, e.to_string())
}

fn net_error(e: NetError) -> UpstreamError {
    UpstreamError::new(UpstreamErrorKind::Transport, None, None, e.to_string())
}

#[async_trait]
impl Upstream for KiroClient {
    async fn generate(&self, payload: &Payload) -> Result<UpstreamStream, UpstreamError> {
        let body = serde_json::to_vec(payload).map_err(|e| {
            UpstreamError::new(UpstreamErrorKind::Protocol, None, None, e.to_string())
        })?;
        let invocation_id = uuid::Uuid::new_v4().to_string();
        let mut attempt = 0u32;
        let mut refreshed = false;
        loop {
            attempt += 1;
            let last = attempt >= MAX_ATTEMPTS;
            let identity = self.tokens.identity().await.map_err(auth_error)?;
            let headers = self.headers(attempt, &invocation_id).await?;
            let dest = Destination::Runtime {
                region: identity.runtime_region,
            };
            let resp = match self.net.post(&dest, "/", headers, body.clone()).await {
                Ok(r) => r,
                Err(NetError::Redirect { status }) => {
                    return Err(UpstreamError::new(
                        UpstreamErrorKind::Transport,
                        Some(status),
                        None,
                        "redirect rejected",
                    ));
                }
                Err(_e) if !last => {
                    tracing::warn!(
                        attempt,
                        error_type = "transport",
                        "upstream request failed, retrying"
                    );
                    tokio::time::sleep(self.backoff(attempt)).await;
                    continue;
                }
                Err(e) => return Err(net_error(e)),
            };
            match resp.status {
                200 => {
                    let ct = resp.content_type().unwrap_or_default();
                    if is_event_stream_content_type(&ct) {
                        let bytes = resp.into_stream().map_err(net_error).boxed();
                        return Ok(UpstreamStream {
                            attempts: attempt,
                            bytes,
                        });
                    }
                    let raw = resp.bytes_limited().await.map_err(net_error)?;
                    let ex = parse_exception_type(&raw);
                    let retryable = ex.as_deref().is_some_and(is_retryable_exception);
                    if retryable && !last {
                        tracing::warn!(
                            attempt,
                            error_type = ex.as_deref().unwrap_or(""),
                            "200 with an exception body, retrying"
                        );
                        tokio::time::sleep(self.backoff(attempt)).await;
                        continue;
                    }
                    let kind = match ex.as_deref() {
                        Some("ThrottlingException" | "TooManyRequestsException") => {
                            UpstreamErrorKind::Throttled
                        }
                        Some(t) if is_retryable_exception(t) => UpstreamErrorKind::Server,
                        Some(_) => UpstreamErrorKind::Client,
                        None => UpstreamErrorKind::Protocol,
                    };
                    return Err(UpstreamError::new(
                        kind,
                        Some(200),
                        ex,
                        parse_exception_message(&raw),
                    ));
                }
                403 => {
                    if !refreshed && !last {
                        self.tokens.invalidate().await;
                        refreshed = true;
                        tracing::info!(
                            attempt,
                            "403 from runtime, credential invalidated, retrying"
                        );
                        continue;
                    }
                    return Err(UpstreamError::new(
                        UpstreamErrorKind::Auth,
                        Some(403),
                        None,
                        "runtime rejected the credential",
                    ));
                }
                status @ (429 | 500..=599) => {
                    let raw = resp.bytes_limited().await.unwrap_or_default();
                    let ex = parse_exception_type(&raw);
                    if !last {
                        tracing::warn!(attempt, status, "upstream error, retrying");
                        tokio::time::sleep(self.backoff(attempt)).await;
                        continue;
                    }
                    let kind = if status == 429 {
                        UpstreamErrorKind::Throttled
                    } else {
                        UpstreamErrorKind::Server
                    };
                    return Err(UpstreamError::new(
                        kind,
                        Some(status),
                        ex,
                        parse_exception_message(&raw),
                    ));
                }
                status => {
                    let raw = resp.bytes_limited().await.unwrap_or_default();
                    return Err(UpstreamError::new(
                        UpstreamErrorKind::Client,
                        Some(status),
                        parse_exception_type(&raw),
                        parse_exception_message(&raw),
                    ));
                }
            }
        }
    }
}

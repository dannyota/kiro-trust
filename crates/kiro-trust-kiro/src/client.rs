//! The Kiro runtime client (spec 3.4). Transcribed from kirocc
//! internal/kiroclient/client.go and backoff.go.

use crate::error::{
    UpstreamError, UpstreamErrorKind, classify_throttle, is_event_stream_content_type,
    is_retryable_exception, parse_exception_message, parse_exception_type,
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
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

pub struct UpstreamStream {
    pub attempts: u32,
    pub bytes: BoxStream<'static, Result<Bytes, UpstreamError>>,
}

#[derive(Clone, Default)]
pub struct AttemptProgress(Arc<AtomicU32>);

impl AttemptProgress {
    pub fn completed(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }

    pub fn record_completed(&self, count: u32) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(count))
            });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryDelay {
    Fallback,
    Wait(Duration),
    Stop(Option<Duration>),
}

pub fn retry_after(headers: &HeaderMap, now: SystemTime) -> RetryDelay {
    let Some(value) = headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    else {
        return RetryDelay::Fallback;
    };
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return match value.parse::<u64>() {
            Ok(seconds) => retry_delay(Duration::from_secs(seconds)),
            Err(_) => RetryDelay::Stop(None),
        };
    }
    match httpdate::parse_http_date(value) {
        Ok(date) => match date.duration_since(now) {
            Ok(delay) => retry_delay(delay),
            Err(_) => RetryDelay::Fallback,
        },
        Err(_) => RetryDelay::Fallback,
    }
}

fn retry_delay(delay: Duration) -> RetryDelay {
    if delay <= Duration::from_secs(60) {
        RetryDelay::Wait(delay)
    } else {
        RetryDelay::Stop(Some(delay))
    }
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

    async fn generate_with_progress(
        &self,
        payload: &Payload,
        progress: &AttemptProgress,
    ) -> Result<UpstreamStream, UpstreamError> {
        let result = self.generate(payload).await;
        progress.record_completed(match &result {
            Ok(stream) => stream.attempts,
            Err(error) => error.attempts,
        });
        result
    }
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
            .map_err(|error| auth_error(error, 0))?
            .map_err(|_| {
                UpstreamError::new(
                    UpstreamErrorKind::Auth,
                    None,
                    None,
                    0,
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

fn auth_error(e: AuthError, attempts: u32) -> UpstreamError {
    UpstreamError::new(
        UpstreamErrorKind::Auth,
        None,
        None,
        attempts,
        None,
        e.to_string(),
    )
}

fn net_error(e: NetError, attempts: u32) -> UpstreamError {
    UpstreamError::new(
        UpstreamErrorKind::Transport,
        None,
        None,
        attempts,
        None,
        e.to_string(),
    )
}

#[async_trait]
impl Upstream for KiroClient {
    async fn generate(&self, payload: &Payload) -> Result<UpstreamStream, UpstreamError> {
        self.generate_inner(payload, None).await
    }

    async fn generate_with_progress(
        &self,
        payload: &Payload,
        progress: &AttemptProgress,
    ) -> Result<UpstreamStream, UpstreamError> {
        self.generate_inner(payload, Some(progress)).await
    }
}

impl KiroClient {
    async fn generate_inner(
        &self,
        payload: &Payload,
        progress: Option<&AttemptProgress>,
    ) -> Result<UpstreamStream, UpstreamError> {
        let body = serde_json::to_vec(payload).map_err(|e| {
            UpstreamError::new(
                UpstreamErrorKind::Protocol,
                None,
                None,
                0,
                None,
                e.to_string(),
            )
        })?;
        let invocation_id = uuid::Uuid::new_v4().to_string();
        let mut attempts = 0u32;
        let mut refreshed = false;
        loop {
            let request_attempt = attempts.saturating_add(1);
            let identity = self
                .tokens
                .identity()
                .await
                .map_err(|error| auth_error(error, attempts))?;
            let headers = self
                .headers(request_attempt, &invocation_id)
                .await
                .map_err(|mut error| {
                    error.attempts = attempts;
                    error
                })?;
            let dest = Destination::Runtime {
                region: identity.runtime_region,
            };
            let post = self.net.post(&dest, "/", headers, body.clone()).await;
            attempts = attempts.saturating_add(1);
            if let Some(progress) = progress {
                progress.record_completed(1);
            }
            let last = attempts >= MAX_ATTEMPTS;
            let resp = match post {
                Ok(r) => r,
                Err(NetError::Redirect { status }) => {
                    return Err(UpstreamError::new(
                        UpstreamErrorKind::Transport,
                        Some(status),
                        None,
                        attempts,
                        None,
                        "redirect rejected",
                    ));
                }
                Err(_e) if !last => {
                    tracing::warn!(
                        attempt = attempts,
                        error_type = "transport",
                        "upstream request failed, retrying"
                    );
                    tokio::time::sleep(self.backoff(attempts)).await;
                    continue;
                }
                Err(e) => return Err(net_error(e, attempts)),
            };
            match resp.status {
                200 => {
                    let ct = resp.content_type().unwrap_or_default();
                    if is_event_stream_content_type(&ct) {
                        let bytes = resp
                            .into_stream()
                            .map_err(move |error| net_error(error, attempts))
                            .boxed();
                        return Ok(UpstreamStream { attempts, bytes });
                    }
                    let raw = resp
                        .bytes_limited()
                        .await
                        .map_err(|error| net_error(error, attempts))?;
                    let ex = parse_exception_type(&raw);
                    let kind = match ex.as_deref() {
                        Some(_)
                            if classify_throttle(200, &raw) == UpstreamErrorKind::ModelCapacity =>
                        {
                            UpstreamErrorKind::ModelCapacity
                        }
                        Some("ThrottlingException" | "TooManyRequestsException") => {
                            UpstreamErrorKind::Throttled
                        }
                        Some(t) if is_retryable_exception(t) => UpstreamErrorKind::Server,
                        Some(_) => UpstreamErrorKind::Client,
                        None => UpstreamErrorKind::Protocol,
                    };
                    let retryable = kind == UpstreamErrorKind::ModelCapacity
                        || ex.as_deref().is_some_and(is_retryable_exception);
                    if retryable && !last {
                        let error_type = if kind == UpstreamErrorKind::ModelCapacity {
                            "model_capacity"
                        } else {
                            ex.as_deref().unwrap_or("")
                        };
                        tracing::warn!(
                            attempt = attempts,
                            error_type,
                            "200 with an exception body, retrying"
                        );
                        tokio::time::sleep(self.backoff(attempts)).await;
                        continue;
                    }
                    return Err(UpstreamError::new(
                        kind,
                        Some(200),
                        ex,
                        attempts,
                        None,
                        parse_exception_message(&raw),
                    ));
                }
                403 => {
                    if !refreshed && !last {
                        self.tokens.invalidate().await;
                        refreshed = true;
                        tracing::info!(
                            attempt = attempts,
                            "403 from runtime, credential invalidated, retrying"
                        );
                        continue;
                    }
                    return Err(UpstreamError::new(
                        UpstreamErrorKind::Auth,
                        Some(403),
                        None,
                        attempts,
                        None,
                        "runtime rejected the credential",
                    ));
                }
                status @ (429 | 500..=599) => {
                    let delay = retry_after(&resp.headers, SystemTime::now());
                    let raw = resp.bytes_limited().await.unwrap_or_default();
                    let ex = parse_exception_type(&raw);
                    let kind = classify_throttle(status, &raw);
                    if let RetryDelay::Stop(delay) = delay {
                        return Err(UpstreamError::new(
                            kind,
                            Some(status),
                            ex,
                            attempts,
                            delay,
                            parse_exception_message(&raw),
                        ));
                    }
                    if !last {
                        tracing::warn!(attempt = attempts, status, "upstream error, retrying");
                        let delay = match delay {
                            RetryDelay::Wait(delay) => delay,
                            RetryDelay::Fallback => self.backoff(attempts),
                            RetryDelay::Stop(_) => unreachable!(),
                        };
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(UpstreamError::new(
                        kind,
                        Some(status),
                        ex,
                        attempts,
                        None,
                        parse_exception_message(&raw),
                    ));
                }
                status => {
                    let raw = resp.bytes_limited().await.unwrap_or_default();
                    return Err(UpstreamError::new(
                        UpstreamErrorKind::Client,
                        Some(status),
                        parse_exception_type(&raw),
                        attempts,
                        None,
                        parse_exception_message(&raw),
                    ));
                }
            }
        }
    }
}

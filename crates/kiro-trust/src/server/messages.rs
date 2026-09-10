//! POST /v1/messages (spec 5.1, 5.3, 5.4, 5.6).

use crate::server::AppState;
use crate::server::error::ApiError;
use crate::server::pump::{Chunk, Primed, Pump};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt as _;
use futures_util::stream;
use kiro_trust_protocol::anthropic::{Request, StreamEvent};
use kiro_trust_protocol::catalog;
use kiro_trust_protocol::estimate;
use kiro_trust_protocol::sse;
use kiro_trust_protocol::translate::request::{BuildOptions, build_payload};
use kiro_trust_protocol::translate::response::{
    Failure, FailureKind, ResponseOptions, ResponseTranslator,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

pub const MAX_MESSAGES: usize = 4096;
pub const MAX_TOOLS: usize = 512;
const KEEPALIVE_EVERY: Duration = Duration::from_secs(15);
const RETRYABLE_INVALID_STATE: &[&str] = &[
    "CONTENT_LENGTH_EXCEEDS_THRESHOLD",
    "INVALID_CONVERSATION_STATE",
    "STALE_CONVERSATION",
];

/// Kiro sees a stable id per Claude Code session, never the raw session id
/// (spec 5.3).
pub fn conversation_id(salt: &[u8; 16], session: Option<&str>) -> String {
    match session {
        Some(s) if !s.is_empty() => {
            Uuid::new_v5(&Uuid::from_bytes(*salt), s.as_bytes()).to_string()
        }
        _ => Uuid::new_v4().to_string(),
    }
}

pub fn has_context_1m_beta(headers: &HeaderMap) -> bool {
    headers
        .get_all("anthropic-beta")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|b| b.trim().starts_with("context-1m"))
}

pub fn parse_request(body: &Bytes) -> Result<Request, ApiError> {
    let req: Request = serde_json::from_slice(body)
        .map_err(|e| ApiError::invalid_request(format!("invalid request body: {e}")))?;
    if req.messages.is_empty() {
        return Err(ApiError::invalid_request("messages must not be empty"));
    }
    if req.messages.len() > MAX_MESSAGES {
        return Err(ApiError::invalid_request(format!(
            "messages exceed the limit of {MAX_MESSAGES}"
        )));
    }
    if req.tools.len() > MAX_TOOLS {
        return Err(ApiError::invalid_request(format!(
            "tools exceed the limit of {MAX_TOOLS}"
        )));
    }
    Ok(req)
}

fn failure_to_error(f: &Failure) -> ApiError {
    match &f.kind {
        FailureKind::Exception { exception_type }
            if matches!(
                exception_type.as_str(),
                "ThrottlingException" | "TooManyRequestsException"
            ) =>
        {
            ApiError::rate_limit(format!("{exception_type}: {}", f.message))
        }
        FailureKind::Exception { exception_type } => {
            ApiError::api_error(format!("{exception_type}: {}", f.message))
        }
        FailureKind::InvalidState { reason } => {
            ApiError::api_error(format!("invalid state {reason}: {}", f.message))
        }
    }
}

fn retryable(f: &Failure) -> bool {
    matches!(&f.kind, FailureKind::InvalidState { reason } if RETRYABLE_INVALID_STATE.contains(&reason.as_str()))
}

pub async fn post_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let started = Instant::now();
    let request_id = Uuid::new_v4();
    let body = body?;
    let req = parse_request(&body)?;
    // `max_tokens` is `#[serde(default)]` on `anthropic::Request` because
    // `parse_request` is shared with `/v1/messages/count_tokens`, which
    // legitimately omits it (spec 5.7). The real Anthropic Messages API
    // requires the field on `/v1/messages`, so the requirement belongs here,
    // at this route's own entry point, rather than in the shared parser or
    // in `anthropic::Request` itself. A present-but-zero value is rejected
    // the same way: the real API also treats `max_tokens: 0` as invalid, and
    // treating the two alike is what lets `ResponseTranslator` use 0 as its
    // own "no client budget" sentinel for the absolute-ceiling fallback
    // (spec 5.4, 5.5) without a second signal for "absent".
    if req.max_tokens == 0 {
        return Err(ApiError::invalid_request("max_tokens is required"));
    }
    let resolved = catalog::resolve(&req.model, has_context_1m_beta(&headers))
        .map_err(|e| ApiError::invalid_request(e.to_string()))?;
    let thinking = req.thinking_enabled() || resolved.thinking;
    let effort = catalog::resolve_effort(&resolved, req.effort(), thinking);
    // Held for the whole request, including the SSE body once streaming
    // starts (spec 5.5): a streaming response must count against the
    // concurrency cap for as long as the connection is open, not just
    // while the upstream call is being primed.
    let permit = state
        .limiter
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::rate_limit("too many concurrent requests"))?;
    let identity = state
        .tokens
        .identity()
        .await
        .map_err(|e| ApiError::authentication(e.to_string()))?;
    let session = headers
        .get("x-claude-code-session-id")
        .and_then(|v| v.to_str().ok());
    let mut built = build_payload(
        &req,
        &BuildOptions {
            profile_arn: Some(identity.profile_arn.clone()),
            model_id: resolved.kiro_model.clone(),
            conversation_id: Some(conversation_id(&state.conversation_salt, session)),
            effort,
        },
    )
    // Raised before `state.upstream.generate` is ever called (below), so a
    // rejected image never reaches the network (spec 5.3, 5.5). The
    // message names the specific limit or media type; it never carries
    // image data (spec 6.4).
    .map_err(|e| ApiError::invalid_request(e.to_string()))?;
    let tool_names = built.tool_names.reverse_map();
    let opts = || ResponseOptions {
        model: resolved.anthropic_model.clone(),
        message_id: format!("msg_{}", &Uuid::new_v4().simple().to_string()[..24]),
        stop_sequences: req.stop_sequences.clone(),
        max_tokens: req.max_tokens,
        tool_names: tool_names.clone(),
        estimated_input_tokens: estimate::count_tokens(&req),
    };
    tracing::info!(
        %request_id,
        path = "/v1/messages",
        model = %resolved.anthropic_model,
        kiro_model = %resolved.kiro_model,
        stream = req.stream,
        input_bytes = body.len(),
        runtime_region = %identity.runtime_region,
        "request"
    );

    // `retry_count` is the invalid-state retry gate (spec 5.4: at most one,
    // and only before output starts); `upstream_attempts` accumulates each
    // `generate()` call's own retries (kiro-trust-kiro's 429/5xx backoff, up
    // to `MAX_ATTEMPTS`), which would otherwise never reach a log line. Both
    // together are what the `retry_count` log field reports.
    let mut retry_count = 0u32;
    let mut upstream_attempts = 0u32;
    loop {
        let upstream = state.upstream.generate(&built.payload).await?;
        upstream_attempts += upstream.attempts.saturating_sub(1);
        let mut pump = Pump::new(upstream.bytes, opts());
        // Snapshot this attempt's request/payload for capture (spec 8.3):
        // set once per loop iteration so a retried attempt captures the
        // payload it actually sent, not an earlier one.
        #[cfg(feature = "capture")]
        {
            pump.capture = state.capture.clone().map(|handle| {
                let seq = handle.next_seq();
                crate::server::capture::CaptureState {
                    handle,
                    seq,
                    request: body.clone(),
                    payload: serde_json::to_vec(&built.payload).unwrap_or_default(),
                    text: String::new(),
                }
            });
        }
        match pump.prime(req.stream).await {
            Primed::Failed(f) if retry_count == 0 && retryable(&f) => {
                retry_count += 1;
                built.payload.conversation_state.conversation_id = None;
                tracing::warn!(
                    %request_id,
                    retry_count,
                    error_type = "invalid_state",
                    "retrying without a conversation id"
                );
                continue;
            }
            Primed::Failed(f) => {
                let err = failure_to_error(&f);
                log_done(
                    &request_id,
                    started,
                    err.status.as_u16(),
                    retry_count + upstream_attempts,
                    &pump,
                    "upstream_failure",
                );
                return Err(err);
            }
            Primed::Broken(e) => {
                let err: ApiError = e.into();
                log_done(
                    &request_id,
                    started,
                    err.status.as_u16(),
                    retry_count + upstream_attempts,
                    &pump,
                    "upstream_broken",
                );
                return Err(err);
            }
            Primed::Ready(first) | Primed::Ended(first) => {
                let retry_count = retry_count + upstream_attempts;
                if req.stream {
                    return Ok(stream_response(
                        request_id,
                        started,
                        retry_count,
                        first,
                        pump,
                        permit,
                    ));
                }
                let mut done = pump.ended_or_stopped();
                while !done {
                    match pump.next().await {
                        Chunk::Events(_) => done = pump.ended_or_stopped(),
                        Chunk::Failed(_events, f) => {
                            let err = failure_to_error(&f);
                            log_done(
                                &request_id,
                                started,
                                err.status.as_u16(),
                                retry_count,
                                &pump,
                                "upstream_failure",
                            );
                            return Err(err);
                        }
                        Chunk::Broken(_events, e) => {
                            let err: ApiError = e.into();
                            log_done(
                                &request_id,
                                started,
                                err.status.as_u16(),
                                retry_count,
                                &pump,
                                "upstream_broken",
                            );
                            return Err(err);
                        }
                        Chunk::Done => done = true,
                    }
                }
                let usage = pump.translator.usage();
                let msg = pump.translator.into_message();
                let response_body =
                    serde_json::to_vec(&msg).expect("OutMessage has no fallible field types");
                #[cfg(feature = "capture")]
                if let Some(c) = pump.capture.take() {
                    c.handle.record(
                        c.seq,
                        &c.request,
                        &c.payload,
                        &pump.raw,
                        &String::from_utf8_lossy(&response_body),
                    );
                }
                log_usage(
                    &request_id,
                    started,
                    200,
                    retry_count,
                    pump.frames,
                    usage.input_tokens,
                    usage.output_tokens,
                    response_body.len(),
                    None,
                );
                return Ok(
                    ([(header::CONTENT_TYPE, "application/json")], response_body).into_response(),
                );
            }
        }
    }
}

// `pump` is only mutated here to seed capture state (spec 8.3), so it is
// unused without that feature.
#[cfg_attr(not(feature = "capture"), allow(unused_mut))]
fn stream_response(
    request_id: Uuid,
    started: Instant,
    retry_count: u32,
    first: Vec<StreamEvent>,
    mut pump: Pump,
    permit: OwnedSemaphorePermit,
) -> Response {
    let mut initial = String::new();
    for ev in &first {
        initial.push_str(&sse::encode(ev));
    }
    // The buffered events from `prime()` are the start of the response the
    // client actually receives, so capture's recorded text (spec 8.3)
    // begins with them too.
    #[cfg(feature = "capture")]
    if let Some(c) = pump.capture.as_mut() {
        c.text.push_str(&initial);
    }
    let output_bytes = Arc::new(AtomicUsize::new(initial.len()));
    let counter = output_bytes.clone();
    // `permit` rides along in the unfold state purely to be dropped when the
    // stream ends or the client disconnects; it is never read.
    let live = stream::unfold(
        (pump, false, permit),
        move |(mut pump, finished, permit)| {
            let counter = counter.clone();
            async move {
                if finished {
                    return None;
                }
                let chunk = match tokio::time::timeout(KEEPALIVE_EVERY, pump.next()).await {
                    Err(_) => {
                        return Some((
                            Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(
                                sse::KEEPALIVE.as_bytes(),
                            )),
                            (pump, false, permit),
                        ));
                    }
                    Ok(c) => c,
                };
                let (text, finished, error_type) = match chunk {
                    Chunk::Events(evs) => {
                        let text: String = evs.iter().map(sse::encode).collect();
                        (text, pump.ended_or_stopped(), None)
                    }
                    Chunk::Failed(evs, f) => {
                        let err = failure_to_error(&f);
                        let mut text: String = evs.iter().map(sse::encode).collect();
                        text.push_str(&sse::encode(&ResponseTranslator::error_event(
                            err.kind,
                            &err.message,
                        )));
                        (text, true, Some("upstream_failure"))
                    }
                    Chunk::Broken(evs, e) => {
                        let err: ApiError = e.into();
                        let mut text: String = evs.iter().map(sse::encode).collect();
                        text.push_str(&sse::encode(&ResponseTranslator::error_event(
                            err.kind,
                            &err.message,
                        )));
                        (text, true, Some("upstream_broken"))
                    }
                    Chunk::Done => (String::new(), true, None),
                };
                counter.fetch_add(text.len(), Ordering::Relaxed);
                #[cfg(feature = "capture")]
                if let Some(c) = pump.capture.as_mut() {
                    c.text.push_str(&text);
                }
                if finished {
                    let usage = pump.translator.usage();
                    log_usage(
                        &request_id,
                        started,
                        200,
                        retry_count,
                        pump.frames,
                        usage.input_tokens,
                        usage.output_tokens,
                        counter.load(Ordering::Relaxed),
                        error_type,
                    );
                    #[cfg(feature = "capture")]
                    if let Some(c) = pump.capture.take() {
                        c.handle
                            .record(c.seq, &c.request, &c.payload, &pump.raw, &c.text);
                    }
                }
                Some((Ok(Bytes::from(text)), (pump, finished, permit)))
            }
        },
    );
    let body = Body::from_stream(
        stream::once(async move { Ok::<Bytes, std::convert::Infallible>(Bytes::from(initial)) })
            .chain(live),
    );
    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

fn log_done(
    request_id: &Uuid,
    started: Instant,
    status: u16,
    retry_count: u32,
    pump: &Pump,
    error_type: &str,
) {
    tracing::warn!(
        %request_id,
        status,
        duration_ms = started.elapsed().as_millis() as u64,
        retry_count,
        frames = pump.frames,
        error_type,
        "request failed"
    );
}

#[allow(clippy::too_many_arguments)]
fn log_usage(
    request_id: &Uuid,
    started: Instant,
    status: u16,
    retry_count: u32,
    frames: u64,
    input_tokens: u64,
    output_tokens: u64,
    output_bytes: usize,
    // Set only when a stream ended in `Chunk::Failed`/`Chunk::Broken` (spec
    // 6.4's `error_type` field): the HTTP status stays 200 either way (the
    // response really did start with a 200), but an operator otherwise has
    // no way to tell a stream failed mid-flight from one that finished
    // cleanly.
    error_type: Option<&str>,
) {
    match error_type {
        Some(error_type) => tracing::info!(
            %request_id,
            status,
            duration_ms = started.elapsed().as_millis() as u64,
            retry_count,
            frames,
            input_tokens,
            output_tokens,
            output_bytes,
            error_type,
            "response"
        ),
        None => tracing::info!(
            %request_id,
            status,
            duration_ms = started.elapsed().as_millis() as u64,
            retry_count,
            frames,
            input_tokens,
            output_tokens,
            output_bytes,
            "response"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A non-UTF-8 `X-Claude-Code-Session-Id` header value fails
    // `HeaderValue::to_str()` in `post_messages`, so it reaches
    // `conversation_id` exactly like a missing header: as `None`. This test
    // exercises `conversation_id` directly, which is where the id-derivation
    // rule (spec 5.3 step 8) actually lives; the header-to-`Option<&str>`
    // step is one line of `post_messages` and is not re-tested here.
    #[test]
    fn conversation_id_derivation() {
        let salt_a = [1u8; 16];
        let salt_b = [2u8; 16];

        // Same session id under the same salt is stable.
        assert_eq!(
            conversation_id(&salt_a, Some("session-abc")),
            conversation_id(&salt_a, Some("session-abc"))
        );

        // Same session id under two different salts differs.
        assert_ne!(
            conversation_id(&salt_a, Some("session-abc")),
            conversation_id(&salt_b, Some("session-abc"))
        );

        // An empty header value yields a fresh id per call.
        assert_ne!(
            conversation_id(&salt_a, Some("")),
            conversation_id(&salt_a, Some(""))
        );

        // A non-UTF-8 header (indistinguishable from an absent one once
        // `to_str()` fails) yields a fresh id per call.
        assert_ne!(
            conversation_id(&salt_a, None),
            conversation_id(&salt_a, None)
        );
    }
}

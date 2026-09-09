//! POST /v1/messages (spec 5.1, 5.3, 5.4, 5.6).

use crate::server::AppState;
use crate::server::error::ApiError;
use crate::server::pump::{Chunk, Primed, Pump};
use axum::Json;
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
    );
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

    let mut retry_count = 0u32;
    loop {
        let upstream = state.upstream.generate(&built.payload).await?;
        let mut pump = Pump::new(upstream.bytes, opts());
        match pump.prime().await {
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
                    retry_count,
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
                    retry_count,
                    &pump,
                    "upstream_broken",
                );
                return Err(err);
            }
            Primed::Ready(first) | Primed::Ended(first) => {
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
                        Chunk::Failed(f) => {
                            log_done(
                                &request_id,
                                started,
                                502,
                                retry_count,
                                &pump,
                                "upstream_failure",
                            );
                            return Err(failure_to_error(&f));
                        }
                        Chunk::Broken(e) => {
                            log_done(
                                &request_id,
                                started,
                                502,
                                retry_count,
                                &pump,
                                "upstream_broken",
                            );
                            return Err(e.into());
                        }
                        Chunk::Done => done = true,
                    }
                }
                let usage = pump.translator.usage();
                log_usage(
                    &request_id,
                    started,
                    200,
                    retry_count,
                    pump.frames,
                    usage.input_tokens,
                    usage.output_tokens,
                    0,
                );
                let msg = pump.translator.into_message();
                return Ok(Json(msg).into_response());
            }
        }
    }
}

fn stream_response(
    request_id: Uuid,
    started: Instant,
    retry_count: u32,
    first: Vec<StreamEvent>,
    pump: Pump,
    permit: OwnedSemaphorePermit,
) -> Response {
    let mut initial = String::new();
    for ev in &first {
        initial.push_str(&sse::encode(ev));
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
                let (text, finished) = match chunk {
                    Chunk::Events(evs) => {
                        let text: String = evs.iter().map(sse::encode).collect();
                        (text, pump.ended_or_stopped())
                    }
                    Chunk::Failed(f) => {
                        let err = failure_to_error(&f);
                        (
                            sse::encode(&ResponseTranslator::error_event(err.kind, &err.message)),
                            true,
                        )
                    }
                    Chunk::Broken(e) => {
                        let err: ApiError = e.into();
                        (
                            sse::encode(&ResponseTranslator::error_event(err.kind, &err.message)),
                            true,
                        )
                    }
                    Chunk::Done => (String::new(), true),
                };
                counter.fetch_add(text.len(), Ordering::Relaxed);
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
                    );
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
) {
    tracing::info!(
        %request_id,
        status,
        duration_ms = started.elapsed().as_millis() as u64,
        retry_count,
        frames,
        input_tokens,
        output_tokens,
        output_bytes,
        "response"
    );
}

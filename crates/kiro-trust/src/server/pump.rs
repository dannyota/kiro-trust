//! Drives one upstream stream through decode → parse → translate, buffering
//! events until the first one so the handler can still answer with an HTTP
//! error (spec 5.4, 5.6).

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use kiro_trust_kiro::{UpstreamError, UpstreamErrorKind};
use kiro_trust_protocol::anthropic::StreamEvent;
use kiro_trust_protocol::eventstream::{EventParser, FrameDecoder};
use kiro_trust_protocol::translate::response::{
    Failure, ResponseOptions, ResponseTranslator, UsageSnapshot,
};
use std::time::Duration;
use tokio::time::Instant;

/// Wall-clock deadline covering only the priming phase: from the first
/// upstream read until the translator has produced its first output
/// (`ResponseTranslator::started`), whichever request path this is (spec
/// 5.4, 5.5). A slow-trickling upstream otherwise pins a concurrency permit
/// indefinitely, because `reqwest`'s read-idle timeout (3.2) resets on every
/// successful read, however small: one byte every 179 s never trips it.
///
/// 120 s is generous next to the upstream connect (10 s) and response
/// header (30 s) timeouts, and comfortably above the time a healthy request
/// takes to produce its first token or thinking chunk, including a heavy
/// `max`-effort reasoning load. It is well under the 180 s per-read idle
/// deadline, so it still meaningfully bounds how long a stalled connection
/// can hold a permit. Once output has started, this deadline no longer
/// applies for the rest of the response: a long generation is legitimate,
/// and the existing per-read idle timeout and SSE keep-alive cover it.
pub const PRIMING_DEADLINE: Duration = Duration::from_secs(120);

pub enum Primed {
    /// First events are ready; the stream continues.
    Ready(Vec<StreamEvent>),
    /// The stream ended cleanly before or at the first event.
    Ended(Vec<StreamEvent>),
    /// Upstream reported a failure before any event.
    Failed(Failure),
    /// Transport or framing error before any event.
    Broken(UpstreamError),
}

pub enum Chunk {
    Events(Vec<StreamEvent>),
    /// Failure after output started: emit the buffered events, then an SSE
    /// error, and stop. The vector holds every event decoded in the same
    /// upstream read that carried the failure, so output from that read is
    /// never dropped alongside it.
    Failed(Vec<StreamEvent>, Failure),
    /// Same as `Failed`, for a transport or framing error.
    Broken(Vec<StreamEvent>, UpstreamError),
    Done,
}

pub struct Pump {
    bytes: BoxStream<'static, Result<Bytes, UpstreamError>>,
    decoder: FrameDecoder,
    parser: EventParser,
    pub translator: ResponseTranslator,
    pub frames: u64,
    ended: bool,
    /// Set once a transport or framing error occurs, and never cleared, so a
    /// `next()` call after a deferred `Broken` (see `prime`) re-surfaces it
    /// instead of reading the stream again. `ResponseTranslator::failure`
    /// plays the same role for an upstream `Failure`.
    broken: Option<UpstreamError>,
    /// Raw upstream bytes, appended to as they arrive (spec 8.3 capture).
    /// Absent unless built with the `capture` feature.
    #[cfg(feature = "capture")]
    pub raw: Vec<u8>,
    /// Per-request capture state set by `server::messages`; consumed and
    /// recorded once the response is complete. Absent unless built with the
    /// `capture` feature.
    #[cfg(feature = "capture")]
    pub capture: Option<crate::server::capture::CaptureState>,
}

impl Pump {
    pub fn new(
        bytes: BoxStream<'static, Result<Bytes, UpstreamError>>,
        opts: ResponseOptions,
    ) -> Self {
        Pump {
            bytes,
            decoder: FrameDecoder::new(),
            parser: EventParser::new(),
            translator: ResponseTranslator::new(opts),
            frames: 0,
            ended: false,
            broken: None,
            #[cfg(feature = "capture")]
            raw: Vec::new(),
            #[cfg(feature = "capture")]
            capture: None,
        }
    }

    pub fn ended_or_stopped(&self) -> bool {
        self.ended || self.translator.stopped()
    }

    fn protocol(msg: String) -> UpstreamError {
        UpstreamError::new(UpstreamErrorKind::Protocol, None, None, 0, None, msg)
    }

    /// Important 3: same shape as an idle-read timeout (spec 5.6's "upstream
    /// 5xx, malformed stream, idle timeout" row already maps `Transport` to
    /// 502 `api_error`), since expiry here means the same thing: no progress
    /// from upstream in time.
    fn priming_timeout() -> UpstreamError {
        UpstreamError::new(
            UpstreamErrorKind::Transport,
            None,
            None,
            0,
            None,
            format!(
                "no output within the {}s priming deadline",
                PRIMING_DEADLINE.as_secs()
            ),
        )
    }

    /// Pull one upstream chunk and translate every complete frame in it.
    pub async fn next(&mut self) -> Chunk {
        // A failure or break recorded by an earlier call outranks `ended`:
        // once either is set it must keep surfacing on every subsequent
        // call, even one made after `self.ended` was also set in the same
        // read that discovered it.
        if let Some(f) = self.translator.failure() {
            return Chunk::Failed(Vec::new(), f.clone());
        }
        if let Some(e) = self.broken.clone() {
            return Chunk::Broken(Vec::new(), e);
        }
        if self.ended || self.translator.stopped() {
            return Chunk::Done;
        }
        let mut out = Vec::new();
        match self.bytes.next().await {
            None => {
                self.ended = true;
                if let Err(e) = self.decoder.finish() {
                    let err = Self::protocol(e.to_string());
                    self.broken = Some(err.clone());
                    return Chunk::Broken(out, err);
                }
                if let Some(ev) = self.parser.finish() {
                    out.extend(self.translator.push(&ev));
                }
                out.extend(self.translator.finish());
                return Chunk::Events(out);
            }
            Some(Err(e)) => {
                self.broken = Some(e.clone());
                return Chunk::Broken(out, e);
            }
            Some(Ok(chunk)) => {
                #[cfg(feature = "capture")]
                self.raw.extend_from_slice(&chunk);
                self.decoder.push(&chunk);
            }
        }
        loop {
            let frame = match self.decoder.next_frame() {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    let err = Self::protocol(e.to_string());
                    self.broken = Some(err.clone());
                    return Chunk::Broken(out, err);
                }
            };
            self.frames += 1;
            let events = match self.parser.parse(&frame) {
                Ok(ev) => ev,
                Err(e) => {
                    let err = Self::protocol(e.to_string());
                    self.broken = Some(err.clone());
                    return Chunk::Broken(out, err);
                }
            };
            for ev in events {
                out.extend(self.translator.push(&ev));
                if let Some(f) = self.translator.failure() {
                    return Chunk::Failed(out, f.clone());
                }
                if self.translator.stopped() {
                    return Chunk::Events(out);
                }
            }
        }
        Chunk::Events(out)
    }

    /// Read until output has started, a clean end, or a failure.
    ///
    /// `streaming` decides what "output has started" means, per spec 5.4:
    ///
    /// - Streaming: any content already buffered as translated events counts
    ///   as started, because those bytes are on the wire once the handler
    ///   flushes them. A failure or break carrying buffered events from the
    ///   same read is handed back as `Ready` rather than `Failed`/`Broken`
    ///   for the same reason (unchanged from before this method took a
    ///   `streaming` argument). The failure itself is not lost: it stays
    ///   recorded on `self.translator` (or `self.broken`), so the caller's
    ///   next `next()` call surfaces it immediately as `Chunk::Failed` or
    ///   `Chunk::Broken`, and the handler emits it as an SSE `error` event
    ///   right after these buffered events.
    /// - Non-streaming: nothing reaches the client until the whole response
    ///   is folded (spec 5.4's non-streaming HTTP-error note), so buffered
    ///   translator events never end this loop early and never accompany a
    ///   failure. A retryable invalid state still gets its one retry even
    ///   after earlier content (a `reasoningContentEvent`, say) has been
    ///   translated internally, because none of it has reached the client.
    ///
    /// A wall-clock deadline (`PRIMING_DEADLINE`) covers this whole phase on
    /// both paths, from the first read until `self.translator.started()`
    /// (Important 3): once real output exists, the deadline no longer
    /// applies, so a long legitimate generation is never cut short by it.
    pub async fn prime<F>(&mut self, streaming: bool, mut observe: F) -> Primed
    where
        F: FnMut(UsageSnapshot),
    {
        let mut buffered = Vec::new();
        let deadline = Instant::now() + PRIMING_DEADLINE;
        loop {
            let chunk = if self.translator.started() {
                self.next().await
            } else {
                match tokio::time::timeout_at(deadline, self.next()).await {
                    Ok(c) => c,
                    Err(_) => {
                        let err = Self::priming_timeout();
                        self.broken = Some(err.clone());
                        return Primed::Broken(err);
                    }
                }
            };
            observe(self.translator.usage_snapshot());
            // Non-streaming never reads `buffered`: `post_messages` only
            // consumes a `Primed::Ready`/`Ended` payload inside its
            // `if req.stream` branch, and folds the non-streaming response
            // straight from `pump.translator`'s own accumulators instead.
            // Skipping the extend keeps this loop from silently doubling
            // peak memory on the non-streaming path (once in the
            // translator's accumulators, again in a growing event vector)
            // now that it runs for the whole response rather than stopping
            // at the first batch.
            match chunk {
                Chunk::Events(ev) => {
                    if streaming {
                        buffered.extend(ev);
                    }
                    if self.ended || self.translator.stopped() {
                        return Primed::Ended(buffered);
                    }
                    if streaming && !buffered.is_empty() {
                        return Primed::Ready(buffered);
                    }
                }
                Chunk::Failed(ev, f) => {
                    if streaming {
                        buffered.extend(ev);
                    }
                    if !streaming || buffered.is_empty() {
                        return Primed::Failed(f);
                    }
                    return Primed::Ready(buffered);
                }
                Chunk::Broken(ev, e) => {
                    if streaming {
                        buffered.extend(ev);
                    }
                    if !streaming || buffered.is_empty() {
                        return Primed::Broken(e);
                    }
                    return Primed::Ready(buffered);
                }
                Chunk::Done => return Primed::Ended(buffered),
            }
        }
    }
}

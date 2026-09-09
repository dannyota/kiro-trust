//! Drives one upstream stream through decode → parse → translate, buffering
//! events until the first one so the handler can still answer with an HTTP
//! error (spec 5.4, 5.6).

use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use kiro_trust_kiro::UpstreamError;
use kiro_trust_protocol::anthropic::StreamEvent;
use kiro_trust_protocol::eventstream::{EventParser, FrameDecoder};
use kiro_trust_protocol::translate::response::{Failure, ResponseOptions, ResponseTranslator};

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
        UpstreamError::new(
            kiro_trust_kiro::UpstreamErrorKind::Protocol,
            None,
            None,
            msg,
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

    /// Read until the first event, a clean end, or a failure.
    ///
    /// A failure or break that arrives carrying buffered events means output
    /// has already started (spec 5.4: the HTTP-error and retry-once rules
    /// apply only before any output), so it is handed back as `Ready` rather
    /// than `Failed`/`Broken`. The failure itself is not lost: it stays
    /// recorded on `self.translator` (or `self.broken`), so the caller's
    /// next `next()` call surfaces it immediately as `Chunk::Failed` or
    /// `Chunk::Broken` and the handler emits it as an SSE `error` event
    /// right after these buffered events. `Failed`/`Broken` with no
    /// buffered events keep meaning what they always meant: no output was
    /// produced, so the caller answers with an HTTP error instead.
    pub async fn prime(&mut self) -> Primed {
        let mut buffered = Vec::new();
        loop {
            match self.next().await {
                Chunk::Events(ev) => {
                    buffered.extend(ev);
                    if self.ended || self.translator.stopped() {
                        return Primed::Ended(buffered);
                    }
                    if !buffered.is_empty() {
                        return Primed::Ready(buffered);
                    }
                }
                Chunk::Failed(ev, f) => {
                    buffered.extend(ev);
                    if buffered.is_empty() {
                        return Primed::Failed(f);
                    }
                    return Primed::Ready(buffered);
                }
                Chunk::Broken(ev, e) => {
                    buffered.extend(ev);
                    if buffered.is_empty() {
                        return Primed::Broken(e);
                    }
                    return Primed::Ready(buffered);
                }
                Chunk::Done => return Primed::Ended(buffered),
            }
        }
    }
}

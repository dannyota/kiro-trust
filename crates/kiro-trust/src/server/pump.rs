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
    /// Failure after output started: emit an SSE error and stop.
    Failed(Failure),
    Broken(UpstreamError),
    Done,
}

pub struct Pump {
    bytes: BoxStream<'static, Result<Bytes, UpstreamError>>,
    decoder: FrameDecoder,
    parser: EventParser,
    pub translator: ResponseTranslator,
    pub frames: u64,
    ended: bool,
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
        if self.ended || self.translator.stopped() {
            return Chunk::Done;
        }
        let mut out = Vec::new();
        match self.bytes.next().await {
            None => {
                self.ended = true;
                if let Err(e) = self.decoder.finish() {
                    return Chunk::Broken(Self::protocol(e.to_string()));
                }
                if let Some(ev) = self.parser.finish() {
                    out.extend(self.translator.push(&ev));
                }
                out.extend(self.translator.finish());
                return Chunk::Events(out);
            }
            Some(Err(e)) => return Chunk::Broken(e),
            Some(Ok(chunk)) => self.decoder.push(&chunk),
        }
        loop {
            let frame = match self.decoder.next_frame() {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => return Chunk::Broken(Self::protocol(e.to_string())),
            };
            self.frames += 1;
            let events = match self.parser.parse(&frame) {
                Ok(ev) => ev,
                Err(e) => return Chunk::Broken(Self::protocol(e.to_string())),
            };
            for ev in events {
                out.extend(self.translator.push(&ev));
                if let Some(f) = self.translator.failure() {
                    return Chunk::Failed(f.clone());
                }
                if self.translator.stopped() {
                    return Chunk::Events(out);
                }
            }
        }
        Chunk::Events(out)
    }

    /// Read until the first event, a clean end, or a failure.
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
                Chunk::Failed(f) => return Primed::Failed(f),
                Chunk::Broken(e) => return Primed::Broken(e),
                Chunk::Done => return Primed::Ended(buffered),
            }
        }
    }
}

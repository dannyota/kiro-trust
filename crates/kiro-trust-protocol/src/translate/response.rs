//! Kiro events → Anthropic streaming events (spec 5.4). One state machine
//! serves both streaming (emit as you go) and non-streaming (fold at the
//! end). Transcribed from kirocc internal/respconv (see NOTICE), minus the
//! advisor, tool-search, and GPT drain paths.

use crate::anthropic::{
    ApiError, BlockStart, Delta, MessageDeltaBody, OutBlock, OutMessage, StopReason, StreamEvent,
    Usage,
};
use crate::kiro::Event;
use serde_json::{Map, Value};
use std::collections::HashMap;

const OPEN_TAG: &str = "<thinking>";
const CLOSE_TAG: &str = "</thinking>";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReportedTokens {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct EstimatedTokens {
    pub input: u64,
    pub output: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct UsageSnapshot {
    pub reported: ReportedTokens,
    pub estimated: EstimatedTokens,
}

/// Absolute cap on accumulated output (text + thinking + tool-call input +
/// redacted content share one `output_chars` counter), independent of the
/// client's `max_tokens`. `/v1/messages` requires `max_tokens` (spec 5.1,
/// 5.6), so this should never bind for a well-formed request; it exists so a
/// future change that makes the field optional again cannot reopen unbounded
/// accumulation (spec 5.5). Far above any legitimate response: at 4 chars
/// per token it allows roughly 8,000,000 accumulated characters.
const ABSOLUTE_MAX_TOKENS: usize = 2_000_000;

#[derive(Clone, Debug)]
pub struct ResponseOptions {
    pub model: String,
    pub message_id: String,
    pub stop_sequences: Vec<String>,
    /// The client's requested budget. 0 (an absent field reaching this far,
    /// or an explicit 0) is treated as "use the absolute ceiling": the
    /// HTTP boundary requires this field for `/v1/messages` (spec 5.1), so 0
    /// should never arrive from a real request; this is defense in depth,
    /// not the primary enforcement path.
    pub max_tokens: u32,
    /// short → original tool names.
    pub tool_names: HashMap<String, String>,
    /// Used for `usage.input_tokens` when no metadata arrives.
    pub estimated_input_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureKind {
    InvalidState { reason: String },
    Exception { exception_type: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Active {
    Text,
    Thinking,
}

#[derive(Clone)]
struct ToolCall {
    id: String,
    name: String,
    input: String,
}

pub struct ResponseTranslator {
    opts: ResponseOptions,
    // accumulated
    text: String,
    thinking: String,
    tool_calls: Vec<ToolCall>,
    redacted: Vec<String>,
    signature: Option<String>,
    has_metadata: bool,
    input_tokens: u64,
    output_tokens: u64,
    cache_read: u64,
    cache_write: u64,
    // limits
    local_stop: Option<(StopReason, Option<String>)>,
    stop_sequences: Vec<String>,
    stop_max_keep: usize,
    stop_pending: String,
    output_chars: usize,
    // thinking tags
    tag_inside: bool,
    tag_buf: String,
    suppress_reasoning: bool,
    // emitter
    started: bool,
    block_index: i64,
    active: Option<Active>,
    visible: bool,
    finished: bool,
    failure: Option<Failure>,
}

impl ResponseTranslator {
    pub fn new(opts: ResponseOptions) -> Self {
        let stop_sequences: Vec<String> = opts
            .stop_sequences
            .iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect();
        let stop_max_keep = stop_sequences
            .iter()
            .map(|s| s.chars().count().saturating_sub(1))
            .max()
            .unwrap_or(0);
        Self {
            opts,
            text: String::new(),
            thinking: String::new(),
            tool_calls: vec![],
            redacted: vec![],
            signature: None,
            has_metadata: false,
            input_tokens: 0,
            output_tokens: 0,
            cache_read: 0,
            cache_write: 0,
            local_stop: None,
            stop_sequences,
            stop_max_keep,
            stop_pending: String::new(),
            output_chars: 0,
            tag_inside: false,
            tag_buf: String::new(),
            suppress_reasoning: false,
            started: false,
            block_index: -1,
            active: None,
            visible: false,
            finished: false,
            failure: None,
        }
    }

    pub fn stopped(&self) -> bool {
        self.local_stop.is_some()
    }
    pub fn started(&self) -> bool {
        self.started
    }
    pub fn has_visible_output(&self) -> bool {
        self.visible
    }
    pub fn failure(&self) -> Option<&Failure> {
        self.failure.as_ref()
    }
    pub fn is_empty_visible_end_turn(&self) -> bool {
        self.local_stop.is_none()
            && (!self.thinking.is_empty() || !self.redacted.is_empty())
            && self.text.is_empty()
            && self.tool_calls.is_empty()
    }

    // ---- accumulation -------------------------------------------------------

    fn latch(&mut self, reason: StopReason, seq: Option<String>) {
        if self.local_stop.is_none() {
            self.local_stop = Some((reason, seq));
        }
    }

    /// The requested budget clamped to the absolute ceiling, or the ceiling
    /// itself when the requested value is 0. Always positive, so the two
    /// callers below never need a separate "enforcement disabled" branch.
    fn effective_max_tokens(&self) -> usize {
        let requested = self.opts.max_tokens as usize;
        if requested == 0 {
            ABSOLUTE_MAX_TOKENS
        } else {
            requested.min(ABSOLUTE_MAX_TOKENS)
        }
    }

    /// kirocc applyMaxTokensBudget: chars / 4 as the token estimate.
    fn apply_max_tokens(&mut self, delta: &str) -> String {
        let budget = self.effective_max_tokens();
        let n = delta.chars().count();
        if (self.output_chars + n) / 4 < budget {
            self.output_chars += n;
            return delta.to_string();
        }
        let remaining = (budget * 4).saturating_sub(self.output_chars);
        if remaining == 0 {
            self.latch(StopReason::MaxTokens, None);
            return String::new();
        }
        if n > remaining {
            self.output_chars += remaining;
            self.latch(StopReason::MaxTokens, None);
            return delta.chars().take(remaining).collect();
        }
        self.output_chars += n;
        if self.output_chars / 4 >= budget {
            self.latch(StopReason::MaxTokens, None);
        }
        delta.to_string()
    }

    fn account_opaque(&mut self, content: &str) {
        self.output_chars += content.chars().count();
        let budget = self.effective_max_tokens();
        if self.local_stop.is_none() && self.output_chars / 4 >= budget {
            self.latch(StopReason::MaxTokens, None);
        }
    }

    /// kirocc applyStopSequenceFilter, holding back a possible prefix.
    fn apply_stop_filter(&mut self, delta: &str) -> String {
        self.stop_pending.push_str(delta);
        for s in self.stop_sequences.clone() {
            if let Some(idx) = self.stop_pending.find(&s) {
                let emit = self.stop_pending[..idx].to_string();
                self.stop_pending.clear();
                self.latch(StopReason::StopSequence, Some(s));
                return emit;
            }
        }
        let count = self.stop_pending.chars().count();
        if count <= self.stop_max_keep {
            return String::new();
        }
        let split_at = self
            .stop_pending
            .char_indices()
            .nth(count - self.stop_max_keep)
            .map(|(i, _)| i)
            .unwrap_or(self.stop_pending.len());
        let emit = self.stop_pending[..split_at].to_string();
        self.stop_pending = self.stop_pending[split_at..].to_string();
        emit
    }

    /// kirocc parseThinkingTags.
    fn parse_tags(&mut self, delta: &str) -> (String, String) {
        if self.tag_buf.is_empty() && !self.tag_inside && !delta.contains('<') {
            return (delta.to_string(), String::new());
        }
        self.tag_buf.push_str(delta);
        let (mut text, mut think) = (String::new(), String::new());
        while !self.tag_buf.is_empty() {
            if self.tag_inside {
                if let Some(idx) = self.tag_buf.find(CLOSE_TAG) {
                    think.push_str(&self.tag_buf[..idx]);
                    self.tag_buf = self.tag_buf[idx + CLOSE_TAG.len()..].to_string();
                    self.tag_inside = false;
                    continue;
                }
                let keep = partial_tag_suffix(&self.tag_buf, CLOSE_TAG);
                let cut = self.tag_buf.len() - keep;
                think.push_str(&self.tag_buf[..cut]);
                self.tag_buf = self.tag_buf[cut..].to_string();
                break;
            }
            if let Some(idx) = self.tag_buf.find(OPEN_TAG) {
                text.push_str(&self.tag_buf[..idx]);
                self.tag_buf = self.tag_buf[idx + OPEN_TAG.len()..].to_string();
                self.tag_inside = true;
                self.suppress_reasoning = true;
                continue;
            }
            let keep = partial_tag_suffix(&self.tag_buf, OPEN_TAG);
            let cut = self.tag_buf.len() - keep;
            text.push_str(&self.tag_buf[..cut]);
            self.tag_buf = self.tag_buf[cut..].to_string();
            break;
        }
        (text, think)
    }

    fn take_thinking(&mut self, thought: &str) -> String {
        let out = self.apply_max_tokens(thought);
        self.thinking.push_str(&out);
        out
    }

    fn take_text(&mut self, text_out: &str) -> String {
        let mut out = text_out.to_string();
        if !self.stop_sequences.is_empty() {
            out = self.apply_stop_filter(&out);
        }
        if !out.is_empty() && self.local_stop.is_none() {
            out = self.apply_max_tokens(&out);
        }
        self.text.push_str(&out);
        out
    }

    // ---- emission -------------------------------------------------------------

    fn ensure_started(&mut self, out: &mut Vec<StreamEvent>) {
        if self.started {
            return;
        }
        self.started = true;
        out.push(StreamEvent::MessageStart {
            message: OutMessage {
                id: self.opts.message_id.clone(),
                kind: "message".into(),
                role: "assistant".into(),
                content: vec![],
                model: self.opts.model.clone(),
                stop_reason: None,
                stop_sequence: None,
                usage: Usage::default(),
            },
        });
    }

    fn close_active(&mut self, out: &mut Vec<StreamEvent>) {
        if self.active.take().is_some() {
            out.push(StreamEvent::ContentBlockStop {
                index: self.block_index as u32,
            });
        }
    }

    fn switch_block(&mut self, kind: Active, out: &mut Vec<StreamEvent>) {
        if self.active == Some(kind) {
            return;
        }
        self.close_active(out);
        self.block_index += 1;
        self.active = Some(kind);
        let content_block = match kind {
            Active::Text => BlockStart::Text {
                text: String::new(),
            },
            Active::Thinking => BlockStart::Thinking {
                thinking: String::new(),
                signature: None,
            },
        };
        out.push(StreamEvent::ContentBlockStart {
            index: self.block_index as u32,
            content_block,
        });
    }

    fn emit_text(&mut self, text: String, out: &mut Vec<StreamEvent>) {
        if text.is_empty() {
            return;
        }
        self.ensure_started(out);
        self.visible = true;
        self.switch_block(Active::Text, out);
        out.push(StreamEvent::ContentBlockDelta {
            index: self.block_index as u32,
            delta: Delta::TextDelta { text },
        });
    }

    fn emit_thinking(&mut self, thinking: String, out: &mut Vec<StreamEvent>) {
        if thinking.is_empty() {
            return;
        }
        self.ensure_started(out);
        self.switch_block(Active::Thinking, out);
        out.push(StreamEvent::ContentBlockDelta {
            index: self.block_index as u32,
            delta: Delta::ThinkingDelta { thinking },
        });
    }

    fn stop_reason(&self) -> (StopReason, Option<String>) {
        match &self.local_stop {
            Some((r, s)) => (*r, s.clone()),
            None if !self.tool_calls.is_empty() => (StopReason::ToolUse, None),
            None => (StopReason::EndTurn, None),
        }
    }

    pub fn usage(&self) -> Usage {
        let (input, output) = if self.input_tokens > 0 || self.output_tokens > 0 {
            (self.input_tokens, self.output_tokens)
        } else {
            let est_out = if self.output_chars == 0 {
                0
            } else {
                (self.output_chars / 4).max(1) as u64
            };
            (self.opts.estimated_input_tokens, est_out)
        };
        Usage {
            input_tokens: input,
            output_tokens: output,
            cache_read_input_tokens: self.cache_read,
            cache_creation_input_tokens: self.cache_write,
        }
    }

    pub fn usage_snapshot(&self) -> UsageSnapshot {
        let mut snapshot = UsageSnapshot {
            reported: ReportedTokens {
                cache_read: self.cache_read,
                cache_write: self.cache_write,
                ..ReportedTokens::default()
            },
            estimated: EstimatedTokens::default(),
        };
        if self.input_tokens > 0 || self.output_tokens > 0 {
            snapshot.reported.input = self.input_tokens;
            snapshot.reported.output = self.output_tokens;
        } else {
            snapshot.estimated.input = self.opts.estimated_input_tokens;
            snapshot.estimated.output = if self.output_chars == 0 {
                0
            } else {
                (self.output_chars / 4).max(1) as u64
            };
        }
        snapshot
    }

    /// Consume one upstream event; returns the streaming events to send.
    pub fn push(&mut self, ev: &Event) -> Vec<StreamEvent> {
        let mut out = Vec::new();
        if self.finished || self.failure.is_some() {
            return out;
        }
        match ev {
            Event::AssistantResponse { content } => {
                if content.is_empty() || self.local_stop.is_some() {
                    return out;
                }
                let (text_out, think_out) = self.parse_tags(content);
                if !think_out.is_empty() {
                    let t = self.take_thinking(&think_out);
                    self.emit_thinking(t, &mut out);
                }
                if !text_out.is_empty() {
                    let t = self.take_text(&text_out);
                    self.emit_text(t, &mut out);
                }
                if self.local_stop.is_some() {
                    out.extend(self.finish());
                }
            }
            Event::ReasoningContent {
                text,
                signature,
                redacted_content,
            } => {
                if let Some(sig) = signature {
                    self.signature = Some(sig.clone());
                }
                if let Some(data) = redacted_content {
                    self.redacted.push(data.clone());
                    self.account_opaque(data);
                    self.ensure_started(&mut out);
                    self.close_active(&mut out);
                    self.block_index += 1;
                    out.push(StreamEvent::ContentBlockStart {
                        index: self.block_index as u32,
                        content_block: BlockStart::RedactedThinking { data: data.clone() },
                    });
                    out.push(StreamEvent::ContentBlockStop {
                        index: self.block_index as u32,
                    });
                    if self.local_stop.is_some() {
                        out.extend(self.finish());
                    }
                    return out;
                }
                if self.suppress_reasoning {
                    return out;
                }
                if !text.is_empty() && self.local_stop.is_none() {
                    let t = self.take_thinking(text);
                    self.emit_thinking(t, &mut out);
                }
                if let Some(sig) = signature
                    && self.active == Some(Active::Thinking)
                {
                    out.push(StreamEvent::ContentBlockDelta {
                        index: self.block_index as u32,
                        delta: Delta::SignatureDelta {
                            signature: sig.clone(),
                        },
                    });
                }
                if self.local_stop.is_some() {
                    out.extend(self.finish());
                }
            }
            Event::ToolUse {
                tool_use_id,
                name,
                input,
            } => {
                if self.local_stop.is_some() {
                    return out;
                }
                let name = self
                    .opts
                    .tool_names
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| name.clone());
                self.account_opaque(input);
                self.tool_calls.push(ToolCall {
                    id: tool_use_id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                });
                self.ensure_started(&mut out);
                self.visible = true;
                self.close_active(&mut out);
                self.block_index += 1;
                out.push(StreamEvent::ContentBlockStart {
                    index: self.block_index as u32,
                    content_block: BlockStart::ToolUse {
                        id: tool_use_id.clone(),
                        name,
                        input: Map::new(),
                    },
                });
                out.push(StreamEvent::ContentBlockDelta {
                    index: self.block_index as u32,
                    delta: Delta::InputJsonDelta {
                        partial_json: input.clone(),
                    },
                });
                out.push(StreamEvent::ContentBlockStop {
                    index: self.block_index as u32,
                });
                if self.local_stop.is_some() {
                    out.extend(self.finish());
                }
            }
            Event::Metadata {
                uncached_input_tokens,
                output_tokens,
                cache_read_input_tokens,
                cache_write_input_tokens,
                ..
            } => {
                let input = uncached_input_tokens.saturating_add(*cache_read_input_tokens);
                if input > 0 || *output_tokens > 0 {
                    self.has_metadata = true;
                    self.input_tokens = input;
                    self.output_tokens = *output_tokens;
                    self.cache_read = *cache_read_input_tokens;
                    self.cache_write = *cache_write_input_tokens;
                } else {
                    self.cache_read = self.cache_read.max(*cache_read_input_tokens);
                    self.cache_write = self.cache_write.max(*cache_write_input_tokens);
                }
            }
            Event::Metering {
                input_tokens,
                output_tokens,
                ..
            } => {
                if !self.has_metadata && (*input_tokens > 0 || *output_tokens > 0) {
                    self.input_tokens = *input_tokens;
                    self.output_tokens = *output_tokens;
                }
            }
            Event::InvalidState { reason, message } => {
                self.failure = Some(Failure {
                    kind: FailureKind::InvalidState {
                        reason: reason.clone(),
                    },
                    message: message.clone(),
                });
            }
            Event::Exception {
                exception_type,
                message,
            } => {
                self.failure = Some(Failure {
                    kind: FailureKind::Exception {
                        exception_type: exception_type.clone(),
                    },
                    message: message.clone(),
                });
            }
            Event::Ignored { .. } => {}
        }
        out
    }

    /// Flush buffers and emit `message_delta` and `message_stop`. Idempotent.
    pub fn finish(&mut self) -> Vec<StreamEvent> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.finished = true;
        self.ensure_started(&mut out);
        // Flush a partial tag buffer. Once a local stop has latched, nothing
        // more is emitted (spec 5.4): the thinking branch is already safe
        // because `apply_max_tokens` returns an empty string once latched,
        // but the text branch needs an explicit guard.
        let remaining = std::mem::take(&mut self.tag_buf);
        if !remaining.is_empty() {
            if self.tag_inside {
                let t = self.take_thinking(&remaining);
                self.emit_thinking(t, &mut out);
            } else if self.local_stop.is_none() {
                let t = self.take_text(&remaining);
                self.emit_text(t, &mut out);
            }
        }
        // Flush the stop-sequence hold-back.
        let pending = std::mem::take(&mut self.stop_pending);
        if !pending.is_empty() && self.local_stop.is_none() {
            let t = self.apply_max_tokens(&pending);
            self.text.push_str(&t);
            self.emit_text(t, &mut out);
        }
        self.close_active(&mut out);
        let (stop_reason, stop_sequence) = self.stop_reason();
        out.push(StreamEvent::MessageDelta {
            delta: MessageDeltaBody {
                stop_reason,
                stop_sequence,
            },
            usage: self.usage(),
        });
        out.push(StreamEvent::MessageStop);
        out
    }

    /// An SSE `error` event for a failure after the stream started.
    pub fn error_event(kind: &str, message: &str) -> StreamEvent {
        StreamEvent::Error {
            error: ApiError {
                kind: kind.into(),
                message: message.into(),
            },
        }
    }

    /// Fold everything into one non-streaming message. Call `finish` first.
    pub fn into_message(mut self) -> OutMessage {
        if !self.finished {
            let _ = self.finish();
        }
        let mut content = Vec::new();
        if !self.thinking.is_empty() {
            content.push(OutBlock::Thinking {
                thinking: self.thinking.clone(),
                signature: self.signature.clone(),
            });
        }
        if !self.text.is_empty() {
            content.push(OutBlock::Text {
                text: self.text.clone(),
            });
        }
        for tc in dedupe_tool_calls(&self.tool_calls) {
            let input = serde_json::from_str::<Value>(&tc.input)
                .unwrap_or_else(|_| Value::Object(Map::new()));
            content.push(OutBlock::ToolUse {
                id: tc.id,
                name: tc.name,
                input,
            });
        }
        for data in &self.redacted {
            content.push(OutBlock::RedactedThinking { data: data.clone() });
        }
        let (stop_reason, stop_sequence) = self.stop_reason();
        OutMessage {
            id: self.opts.message_id.clone(),
            kind: "message".into(),
            role: "assistant".into(),
            content,
            model: self.opts.model.clone(),
            stop_reason: Some(stop_reason),
            stop_sequence,
            usage: self.usage(),
        }
    }
}

/// Longest suffix of `s` that is a proper prefix of `tag`.
fn partial_tag_suffix(s: &str, tag: &str) -> usize {
    let max = (tag.len() - 1).min(s.len());
    for n in (1..=max).rev() {
        if s.is_char_boundary(s.len() - n) && s[s.len() - n..] == tag[..n] {
            return n;
        }
    }
    0
}

/// kirocc DeduplicateToolCalls: per id keep the longest input, then drop
/// exact name+input repeats (whitespace-normalized).
fn dedupe_tool_calls(calls: &[ToolCall]) -> Vec<ToolCall> {
    let mut by_id: Vec<ToolCall> = Vec::new();
    for c in calls {
        if let Some(existing) = by_id.iter_mut().find(|e| e.id == c.id) {
            if c.input.len() > existing.input.len() {
                *existing = c.clone();
            }
        } else {
            by_id.push(c.clone());
        }
    }
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out = Vec::new();
    for c in by_id {
        let normalized = serde_json::from_str::<Value>(&c.input)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| c.input.clone());
        let key = (c.name.clone(), normalized);
        if !seen.contains(&key) {
            seen.push(key);
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{BlockStart, Delta, StreamEvent};
    use crate::kiro::Event;

    fn opts() -> ResponseOptions {
        ResponseOptions {
            model: "claude-sonnet-4-6".into(),
            message_id: "msg_test".into(),
            stop_sequences: vec![],
            max_tokens: 0,
            tool_names: Default::default(),
            estimated_input_tokens: 7,
        }
    }
    fn text(s: &str) -> Event {
        Event::AssistantResponse { content: s.into() }
    }

    #[test]
    fn usage_snapshot_separates_sources() {
        let mut estimated = ResponseTranslator::new(opts());
        estimated.push(&text("four"));
        assert_eq!(estimated.usage_snapshot().reported.input, 0);
        assert_eq!(estimated.usage_snapshot().estimated.output, 1);

        let mut reported = ResponseTranslator::new(opts());
        reported.push(&Event::Metering {
            credits: 0.0,
            input_tokens: 4,
            output_tokens: 1,
        });
        assert_eq!(reported.usage_snapshot().reported.input, 4);
        assert_eq!(reported.usage_snapshot().reported.output, 1);
        assert_eq!(reported.usage_snapshot().estimated.input, 0);
    }

    #[test]
    fn cache_write_only_keeps_input_estimated() {
        let mut translator = ResponseTranslator::new(opts());
        translator.push(&Event::Metadata {
            uncached_input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            cache_read_input_tokens: 0,
            cache_write_input_tokens: 5,
        });
        let snapshot = translator.usage_snapshot();
        assert_eq!(snapshot.reported.input, 0);
        assert_eq!(snapshot.reported.cache_write, 5);
        assert_eq!(snapshot.estimated.input, opts().estimated_input_tokens);
    }
    fn names(evs: &[StreamEvent]) -> Vec<&'static str> {
        evs.iter().map(StreamEvent::event_name).collect()
    }
    fn deltas_text(evs: &[StreamEvent]) -> String {
        evs.iter()
            .filter_map(|e| match e {
                StreamEvent::ContentBlockDelta {
                    delta: Delta::TextDelta { text },
                    ..
                } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    // kirocc TestSSEWriter_TextOnly + issue #116: frames concatenate verbatim.
    #[test]
    fn text_frames_concatenate_verbatim_across_seams() {
        let mut t = ResponseTranslator::new(opts());
        let mut all = Vec::new();
        for chunk in ["pas", "sword succ", "eeded"] {
            all.extend(t.push(&text(chunk)));
        }
        all.extend(t.push(&Event::Metadata {
            uncached_input_tokens: 10,
            output_tokens: 4,
            total_tokens: 14,
            cache_read_input_tokens: 2,
            cache_write_input_tokens: 1,
        }));
        all.extend(t.finish());
        assert_eq!(
            names(&all),
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop"
            ]
        );
        assert_eq!(deltas_text(&all), "password succeeded");
        let StreamEvent::MessageStart { message } = &all[0] else {
            panic!()
        };
        assert_eq!(message.usage, Usage::default());
        assert_eq!(message.model, "claude-sonnet-4-6");
        let StreamEvent::MessageDelta { delta, usage } = &all[6] else {
            panic!()
        };
        assert_eq!(delta.stop_reason, StopReason::EndTurn);
        assert_eq!(
            *usage,
            Usage {
                input_tokens: 12,
                output_tokens: 4,
                cache_read_input_tokens: 2,
                cache_creation_input_tokens: 1
            }
        );
        assert!(!t.stopped());
    }

    // kirocc TestSSEWriter_ThinkingWithSignature, TestSSEWriter_ToolUse
    #[test]
    fn thinking_then_text_then_tool_use_blocks() {
        let mut o = opts();
        o.tool_names
            .insert("short_x".into(), "very_long_original_name".into());
        let mut t = ResponseTranslator::new(o);
        let mut all = Vec::new();
        all.extend(t.push(&Event::ReasoningContent {
            text: "let me".into(),
            signature: None,
            redacted_content: None,
        }));
        all.extend(t.push(&Event::ReasoningContent {
            text: " think".into(),
            signature: Some("sig1".into()),
            redacted_content: None,
        }));
        all.extend(t.push(&text("answer")));
        all.extend(t.push(&Event::ToolUse {
            tool_use_id: "t1".into(),
            name: "short_x".into(),
            input: r#"{"a":1}"#.into(),
        }));
        all.extend(t.finish());
        assert_eq!(
            names(&all),
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        assert!(matches!(
            &all[1],
            StreamEvent::ContentBlockStart {
                index: 0,
                content_block: BlockStart::Thinking { .. }
            }
        ));
        assert!(
            matches!(&all[4], StreamEvent::ContentBlockDelta { delta: Delta::SignatureDelta { signature }, .. } if signature == "sig1")
        );
        assert!(
            matches!(&all[9], StreamEvent::ContentBlockStart { index: 2, content_block: BlockStart::ToolUse { name, .. } } if name == "very_long_original_name")
        );
        assert!(
            matches!(&all[10], StreamEvent::ContentBlockDelta { delta: Delta::InputJsonDelta { partial_json }, .. } if partial_json == r#"{"a":1}"#)
        );
        let StreamEvent::MessageDelta { delta, .. } = &all[12] else {
            panic!()
        };
        assert_eq!(delta.stop_reason, StopReason::ToolUse);
        assert!(t.has_visible_output());
    }

    // kirocc TestAccumulator_ThinkingViaTags_SplitAcrossChunks, TestSSEWriter_ThinkingViaTags
    #[test]
    fn thinking_tags_split_across_chunks() {
        let mut t = ResponseTranslator::new(opts());
        let mut all = Vec::new();
        for chunk in ["<thin", "king>deep</thi", "nking>visible"] {
            all.extend(t.push(&text(chunk)));
        }
        all.extend(t.push(&Event::ReasoningContent {
            text: "ignored".into(),
            signature: None,
            redacted_content: None,
        }));
        all.extend(t.finish());
        let thinking: String = all
            .iter()
            .filter_map(|e| match e {
                StreamEvent::ContentBlockDelta {
                    delta: Delta::ThinkingDelta { thinking },
                    ..
                } => Some(thinking.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(thinking, "deep");
        assert_eq!(deltas_text(&all), "visible");
    }

    // kirocc TestAccumulator_StopSequence, _StopSequence_EmptyStringIgnored
    #[test]
    fn stop_sequence_matches_across_chunk_boundary() {
        let mut o = opts();
        o.stop_sequences = vec!["".into(), "END".into()];
        let mut t = ResponseTranslator::new(o);
        let mut all = Vec::new();
        all.extend(t.push(&text("hello E")));
        assert_eq!(
            deltas_text(&all),
            "hello",
            "holds back max(len)-1 chars as a possible prefix"
        );
        all.extend(t.push(&text("ND more")));
        assert!(t.stopped());
        assert_eq!(deltas_text(&all), "hello ");
        let StreamEvent::MessageDelta { delta, .. } = all
            .iter()
            .find(|e| matches!(e, StreamEvent::MessageDelta { .. }))
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(delta.stop_reason, StopReason::StopSequence);
        assert_eq!(delta.stop_sequence.as_deref(), Some("END"));
        assert!(all.iter().any(|e| matches!(e, StreamEvent::MessageStop)));
        assert!(
            t.push(&text("late")).is_empty(),
            "nothing after a local stop"
        );
        assert!(t.finish().is_empty(), "finish is idempotent");
    }

    // kirocc TestAccumulator_MaxTokens, _MaxTokens_ThinkingCountsTowardBudget
    #[test]
    fn max_tokens_truncates_by_chars_over_four() {
        let mut o = opts();
        o.max_tokens = 2;
        let mut t = ResponseTranslator::new(o);
        let all = t.push(&text("abcdefghijkl"));
        assert_eq!(deltas_text(&all), "abcdefgh");
        assert!(t.stopped());
        let StreamEvent::MessageDelta { delta, usage } = all
            .iter()
            .find(|e| matches!(e, StreamEvent::MessageDelta { .. }))
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(delta.stop_reason, StopReason::MaxTokens);
        assert_eq!(
            usage.input_tokens, 7,
            "estimate used when no metadata arrived"
        );
        assert_eq!(usage.output_tokens, 2);
    }

    // Critical fix: the absolute ceiling latches even when the client's
    // budget is 0. `/v1/messages` requires `max_tokens` (spec 5.1), so 0
    // should never reach here in production; this proves the defense in
    // depth holds if it ever does, without relying on the client's value. A
    // single delta far larger than the ceiling must leave the accumulator
    // itself bounded, not merely flip a flag, which is the actual memory
    // fix: `self.text` never grows past the ceiling regardless of how much
    // more the delta carried.
    #[test]
    fn absolute_ceiling_latches_and_bounds_the_accumulator_when_max_tokens_is_zero() {
        let mut t = ResponseTranslator::new(opts()); // opts().max_tokens == 0
        let huge = "a".repeat(ABSOLUTE_MAX_TOKENS * 4 + 1);
        let all = t.push(&text(&huge));
        assert!(t.stopped(), "the absolute ceiling must latch a stop");
        let StreamEvent::MessageDelta { delta, .. } = all
            .iter()
            .find(|e| matches!(e, StreamEvent::MessageDelta { .. }))
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(delta.stop_reason, StopReason::MaxTokens);
        let emitted = deltas_text(&all);
        assert_eq!(
            emitted.len(),
            ABSOLUTE_MAX_TOKENS * 4,
            "the accumulator is capped at the ceiling, not merely flagged"
        );
        assert!(
            emitted.len() < huge.len(),
            "far less than the oversized input was retained"
        );
    }

    // Regression: `finish()` must not flush a buffered `<thinking>`-tag
    // prefix as text once a local stop has latched (spec 5.4 "nothing after
    // a stop"). Covers a max_tokens latch and a stop_sequence latch, each
    // with a partial open-tag left in the buffer.
    #[test]
    fn nothing_is_flushed_after_a_latched_stop() {
        let mut o = opts();
        o.max_tokens = 2;
        let mut t = ResponseTranslator::new(o);
        let all = t.push(&text("abcdefgh<thin"));
        assert_eq!(deltas_text(&all), "abcdefgh");
        assert!(matches!(
            all[all.len() - 2],
            StreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(all[all.len() - 1], StreamEvent::MessageStop));

        let mut o = opts();
        o.stop_sequences = vec!["END".into()];
        let mut t = ResponseTranslator::new(o);
        let all = t.push(&text("xEND<thin"));
        assert_eq!(deltas_text(&all), "x");
    }

    // kirocc TestAccumulator_MeteringFallback, _EmptyMetadataDoesNotOverrideMetering
    #[test]
    fn metering_fills_usage_when_metadata_is_empty() {
        let mut t = ResponseTranslator::new(opts());
        t.push(&Event::Metering {
            credits: 0.1,
            input_tokens: 30,
            output_tokens: 3,
        });
        // Cache creation reported alone is not usable token usage; it must not erase metering.
        t.push(&Event::Metadata {
            uncached_input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            cache_read_input_tokens: 0,
            cache_write_input_tokens: 5,
        });
        t.push(&text("x"));
        t.finish();
        assert_eq!(
            t.usage(),
            Usage {
                input_tokens: 30,
                output_tokens: 3,
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 5
            }
        );
        // A metadata event with any input or output count is authoritative, as in kirocc.
        let mut t = ResponseTranslator::new(opts());
        t.push(&Event::Metering {
            credits: 0.1,
            input_tokens: 30,
            output_tokens: 3,
        });
        t.push(&Event::Metadata {
            uncached_input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            cache_read_input_tokens: 5,
            cache_write_input_tokens: 0,
        });
        t.finish();
        assert_eq!(
            t.usage(),
            Usage {
                input_tokens: 5,
                output_tokens: 0,
                cache_read_input_tokens: 5,
                cache_creation_input_tokens: 0
            }
        );
    }

    // Regression: `uncached_input_tokens + cache_read_input_tokens` must not
    // panic (debug) or wrap (release) when upstream sends adversarial u64
    // values; the sum must saturate at u64::MAX.
    #[test]
    fn metadata_token_counts_saturate() {
        let mut t = ResponseTranslator::new(opts());
        t.push(&Event::Metadata {
            uncached_input_tokens: u64::MAX,
            output_tokens: 0,
            total_tokens: 0,
            cache_read_input_tokens: 1,
            cache_write_input_tokens: 0,
        });
        assert_eq!(t.usage().input_tokens, u64::MAX);
    }

    #[test]
    fn upstream_failures_are_reported_not_emitted() {
        let mut t = ResponseTranslator::new(opts());
        assert!(
            t.push(&Event::Exception {
                exception_type: "ThrottlingException".into(),
                message: "slow".into()
            })
            .is_empty()
        );
        assert!(
            matches!(t.failure(), Some(Failure { kind: FailureKind::Exception { exception_type }, .. }) if exception_type == "ThrottlingException")
        );
        assert!(!t.started());
        let mut t = ResponseTranslator::new(opts());
        t.push(&text("partial"));
        t.push(&Event::InvalidState {
            reason: "STALE_CONVERSATION".into(),
            message: "m".into(),
        });
        assert!(t.started());
        assert!(
            matches!(t.failure(), Some(Failure { kind: FailureKind::InvalidState { reason }, .. }) if reason == "STALE_CONVERSATION")
        );
    }

    // kirocc TestBuildNonStreamingResponse_WithThinking, _WithToolUse, _CacheTokens, DeduplicateToolCalls
    #[test]
    fn folds_into_a_message() {
        let mut t = ResponseTranslator::new(opts());
        t.push(&Event::ReasoningContent {
            text: "th".into(),
            signature: Some("s".into()),
            redacted_content: None,
        });
        t.push(&text("hi"));
        t.push(&Event::ToolUse {
            tool_use_id: "t1".into(),
            name: "Read".into(),
            input: r#"{"a":1}"#.into(),
        });
        t.push(&Event::ToolUse {
            tool_use_id: "t1".into(),
            name: "Read".into(),
            input: r#"{"a":1,"b":2}"#.into(),
        });
        t.push(&Event::ToolUse {
            tool_use_id: "t2".into(),
            name: "Read".into(),
            input: r#"{ "a":1, "b":2 }"#.into(),
        });
        t.push(&Event::ToolUse {
            tool_use_id: "t3".into(),
            name: "Bad".into(),
            input: "not json".into(),
        });
        t.push(&Event::Metadata {
            uncached_input_tokens: 1,
            output_tokens: 2,
            total_tokens: 3,
            cache_read_input_tokens: 4,
            cache_write_input_tokens: 5,
        });
        t.finish();
        let m = t.into_message();
        assert_eq!(m.id, "msg_test");
        assert_eq!(m.kind, "message");
        assert_eq!(m.role, "assistant");
        assert_eq!(m.stop_reason, Some(StopReason::ToolUse));
        let json = serde_json::to_value(&m.content).unwrap();
        assert_eq!(
            json[0],
            serde_json::json!({"type": "thinking", "thinking": "th", "signature": "s"})
        );
        assert_eq!(json[1], serde_json::json!({"type": "text", "text": "hi"}));
        assert_eq!(
            json[2],
            serde_json::json!({"type": "tool_use", "id": "t1", "name": "Read", "input": {"a": 1, "b": 2}}),
            "longest input per id wins; same name+args deduped"
        );
        assert_eq!(
            json[3],
            serde_json::json!({"type": "tool_use", "id": "t3", "name": "Bad", "input": {}})
        );
        assert_eq!(json.as_array().unwrap().len(), 4);
        assert_eq!(m.usage.cache_creation_input_tokens, 5);
    }

    #[test]
    fn thinking_only_is_reported_as_empty_visible_end_turn() {
        let mut t = ResponseTranslator::new(opts());
        t.push(&Event::ReasoningContent {
            text: "only".into(),
            signature: None,
            redacted_content: None,
        });
        t.finish();
        assert!(t.is_empty_visible_end_turn());
        assert!(!t.has_visible_output());
    }
}

//! AWS EventStream framing (spec 7.5) and Kiro event decoding.
//!
//! Frame: 12-byte prelude (total_length u32 BE, headers_length u32 BE,
//! prelude CRC32 u32 BE over the first 8 bytes), headers, payload, and a
//! message CRC32 u32 BE over everything before it. CRC is IEEE. Header:
//! name length u8, name, type u8, value. This is one of the fuzz targets.

use crate::kiro::Event;
use serde_json::Value;

/// kirocc `maxFrameSize`; the AWS spec allows 16 MiB, Kiro never nears 4.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// Spec 5.5: tool input accumulation per call.
pub const MAX_TOOL_INPUT_BYTES: usize = 16 * 1024 * 1024;
const PRELUDE_LEN: usize = 12;
const MIN_FRAME_LEN: u32 = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderValue {
    Bool(bool),
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Bytes(Vec<u8>),
    String(String),
    Timestamp(i64),
    Uuid([u8; 16]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub headers: Vec<(String, HeaderValue)>,
    pub payload: Vec<u8>,
}

impl Frame {
    fn header_str(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(n, v)| match v {
            HeaderValue::String(s) if n == name => Some(s.as_str()),
            _ => None,
        })
    }
    pub fn message_type(&self) -> Option<&str> {
        self.header_str(":message-type")
    }
    pub fn event_type(&self) -> Option<&str> {
        self.header_str(":event-type")
    }
    pub fn exception_type(&self) -> Option<&str> {
        self.header_str(":exception-type")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("prelude CRC mismatch: computed {computed:08x}, frame says {expected:08x}")]
    PreludeCrc { computed: u32, expected: u32 },
    #[error("message CRC mismatch: computed {computed:08x}, frame says {expected:08x}")]
    MessageCrc { computed: u32, expected: u32 },
    #[error("frame total_length {total} exceeds {max}")]
    TooLarge { total: u32, max: usize },
    #[error("frame total_length {total} is below the 16-byte minimum")]
    TooSmall { total: u32 },
    #[error("headers_length {headers} exceeds the frame body")]
    HeadersOverrun { headers: u32 },
    #[error("malformed header at offset {offset}")]
    BadHeader { offset: usize },
    #[error("stream ended inside a frame with {pending} bytes pending")]
    Truncated { pending: usize },
}

#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// Bytes consumed from the front of `buf` but not yet drained.
    start: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start * 2 > self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    pub fn pending(&self) -> usize {
        self.buf.len() - self.start
    }

    pub fn finish(&self) -> Result<(), FrameError> {
        match self.pending() {
            0 => Ok(()),
            pending => Err(FrameError::Truncated { pending }),
        }
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        let data = &self.buf[self.start..];
        if data.len() < PRELUDE_LEN {
            return Ok(None);
        }
        let total = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let headers_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let expected = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let computed = crc32fast::hash(&data[..8]);
        if computed != expected {
            return Err(FrameError::PreludeCrc { computed, expected });
        }
        if total < MIN_FRAME_LEN {
            return Err(FrameError::TooSmall { total });
        }
        if total as usize > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge {
                total,
                max: MAX_FRAME_BYTES,
            });
        }
        let body_len = total as usize - PRELUDE_LEN;
        if headers_len as usize > body_len - 4 {
            return Err(FrameError::HeadersOverrun {
                headers: headers_len,
            });
        }
        if data.len() < total as usize {
            return Ok(None);
        }
        let frame_bytes = &data[..total as usize];
        let msg_expected = u32::from_be_bytes([
            frame_bytes[total as usize - 4],
            frame_bytes[total as usize - 3],
            frame_bytes[total as usize - 2],
            frame_bytes[total as usize - 1],
        ]);
        let msg_computed = crc32fast::hash(&frame_bytes[..total as usize - 4]);
        if msg_computed != msg_expected {
            return Err(FrameError::MessageCrc {
                computed: msg_computed,
                expected: msg_expected,
            });
        }
        let headers = parse_headers(&frame_bytes[PRELUDE_LEN..PRELUDE_LEN + headers_len as usize])?;
        let payload = frame_bytes[PRELUDE_LEN + headers_len as usize..total as usize - 4].to_vec();
        self.start += total as usize;
        Ok(Some(Frame { headers, payload }))
    }
}

fn parse_headers(mut data: &[u8]) -> Result<Vec<(String, HeaderValue)>, FrameError> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while !data.is_empty() {
        let name_len = data[0] as usize;
        if data.len() < 1 + name_len + 1 {
            return Err(FrameError::BadHeader { offset });
        }
        let name = std::str::from_utf8(&data[1..1 + name_len])
            .map_err(|_| FrameError::BadHeader { offset })?
            .to_string();
        let kind = data[1 + name_len];
        let mut rest = &data[2 + name_len..];
        let take = |rest: &mut &[u8], n: usize| -> Result<Vec<u8>, FrameError> {
            if rest.len() < n {
                return Err(FrameError::BadHeader { offset });
            }
            let (head, tail) = rest.split_at(n);
            *rest = tail;
            Ok(head.to_vec())
        };
        let value = match kind {
            0 => HeaderValue::Bool(true),
            1 => HeaderValue::Bool(false),
            2 => HeaderValue::Byte(take(&mut rest, 1)?[0] as i8),
            3 => HeaderValue::Short(i16::from_be_bytes(take(&mut rest, 2)?.try_into().unwrap())),
            4 => HeaderValue::Int(i32::from_be_bytes(take(&mut rest, 4)?.try_into().unwrap())),
            5 => HeaderValue::Long(i64::from_be_bytes(take(&mut rest, 8)?.try_into().unwrap())),
            6 | 7 => {
                let len = u16::from_be_bytes(take(&mut rest, 2)?.try_into().unwrap()) as usize;
                let bytes = take(&mut rest, len)?;
                if kind == 6 {
                    HeaderValue::Bytes(bytes)
                } else {
                    HeaderValue::String(
                        String::from_utf8(bytes).map_err(|_| FrameError::BadHeader { offset })?,
                    )
                }
            }
            8 => {
                HeaderValue::Timestamp(i64::from_be_bytes(take(&mut rest, 8)?.try_into().unwrap()))
            }
            9 => HeaderValue::Uuid(take(&mut rest, 16)?.try_into().unwrap()),
            _ => return Err(FrameError::BadHeader { offset }),
        };
        offset += data.len() - rest.len();
        data = rest;
        out.push((name, value));
    }
    Ok(out)
}

// ---- Encoding (tests, fixtures, xtask) ---------------------------------------
// Transcribed from kirocc internal/testutil/testutil.go BuildFrame/AssembleFrame.

pub fn push_header(buf: &mut Vec<u8>, name: &str, value: &HeaderValue) {
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());
    match value {
        HeaderValue::Bool(true) => buf.push(0),
        HeaderValue::Bool(false) => buf.push(1),
        HeaderValue::Byte(b) => {
            buf.push(2);
            buf.push(*b as u8);
        }
        HeaderValue::Short(v) => {
            buf.push(3);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        HeaderValue::Int(v) => {
            buf.push(4);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        HeaderValue::Long(v) => {
            buf.push(5);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        HeaderValue::Bytes(b) => {
            buf.push(6);
            buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
            buf.extend_from_slice(b);
        }
        HeaderValue::String(s) => {
            buf.push(7);
            buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        HeaderValue::Timestamp(v) => {
            buf.push(8);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        HeaderValue::Uuid(u) => {
            buf.push(9);
            buf.extend_from_slice(u);
        }
    }
}

pub fn encode_frame(headers: &[u8], payload: &[u8]) -> Vec<u8> {
    let total = (PRELUDE_LEN + headers.len() + payload.len() + 4) as u32;
    let mut frame = Vec::with_capacity(total as usize);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    let prelude_crc = crc32fast::hash(&frame[..8]);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(headers);
    frame.extend_from_slice(payload);
    let msg_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&msg_crc.to_be_bytes());
    frame
}

pub fn encode_event_frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = Vec::new();
    push_header(
        &mut headers,
        ":message-type",
        &HeaderValue::String("event".into()),
    );
    push_header(
        &mut headers,
        ":event-type",
        &HeaderValue::String(event_type.into()),
    );
    push_header(
        &mut headers,
        ":content-type",
        &HeaderValue::String("application/json".into()),
    );
    encode_frame(&headers, payload)
}

pub fn encode_exception_frame(exception_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = Vec::new();
    push_header(
        &mut headers,
        ":message-type",
        &HeaderValue::String("exception".into()),
    );
    push_header(
        &mut headers,
        ":exception-type",
        &HeaderValue::String(exception_type.into()),
    );
    push_header(
        &mut headers,
        ":content-type",
        &HeaderValue::String("application/json".into()),
    );
    encode_frame(&headers, payload)
}

// ---- Events ------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("{event_type} payload is not valid JSON")]
    BadJson { event_type: String },
    #[error("tool input for {tool_use_id} exceeds {max} bytes")]
    ToolInputTooLarge { tool_use_id: String, max: usize },
}

#[derive(Default)]
struct ToolUseAccumulator {
    id: String,
    name: String,
    input: String,
}

impl ToolUseAccumulator {
    fn take(&mut self) -> Event {
        Event::ToolUse {
            tool_use_id: std::mem::take(&mut self.id),
            name: std::mem::take(&mut self.name),
            input: std::mem::take(&mut self.input),
        }
    }
}

#[derive(Default)]
pub struct EventParser {
    tool: ToolUseAccumulator,
}

fn u64_field(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl EventParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(&mut self, frame: &Frame) -> Result<Vec<Event>, EventError> {
        let json = |event_type: &str| -> Result<Value, EventError> {
            serde_json::from_slice(&frame.payload).map_err(|_| EventError::BadJson {
                event_type: event_type.to_string(),
            })
        };
        if frame.message_type() == Some("exception") {
            let v = json("exception").unwrap_or(Value::Null);
            return Ok(vec![Event::Exception {
                exception_type: frame.exception_type().unwrap_or("").to_string(),
                message: str_field(&v, "message").unwrap_or_default(),
            }]);
        }
        let Some(event_type) = frame.event_type() else {
            return Ok(vec![]);
        };
        Ok(match event_type {
            "assistantResponseEvent" => {
                let v = json(event_type)?;
                vec![Event::AssistantResponse {
                    content: str_field(&v, "content").unwrap_or_default(),
                }]
            }
            "reasoningContentEvent" => {
                let v = json(event_type)?;
                vec![Event::ReasoningContent {
                    text: str_field(&v, "text").unwrap_or_default(),
                    signature: str_field(&v, "signature"),
                    redacted_content: str_field(&v, "redactedContent"),
                }]
            }
            "toolUseEvent" => {
                let Ok(v) = json(event_type) else {
                    return Ok(vec![]);
                };
                self.tool_use(&v)?
            }
            "metadataEvent" => {
                let Ok(v) = json(event_type) else {
                    return Ok(vec![]);
                };
                let tu = v.get("tokenUsage").cloned().unwrap_or(Value::Null);
                vec![Event::Metadata {
                    uncached_input_tokens: u64_field(&tu, "uncachedInputTokens"),
                    output_tokens: u64_field(&tu, "outputTokens"),
                    total_tokens: u64_field(&tu, "totalTokens"),
                    cache_read_input_tokens: u64_field(&tu, "cacheReadInputTokens"),
                    cache_write_input_tokens: u64_field(&tu, "cacheWriteInputTokens"),
                }]
            }
            "meteringEvent" => {
                let Ok(v) = json(event_type) else {
                    return Ok(vec![]);
                };
                vec![Event::Metering {
                    credits: v.get("usage").and_then(Value::as_f64).unwrap_or(0.0),
                    input_tokens: u64_field(&v, "inputTokens"),
                    output_tokens: u64_field(&v, "outputTokens"),
                }]
            }
            "invalidStateEvent" => {
                let v = json(event_type)?;
                vec![Event::InvalidState {
                    reason: str_field(&v, "reason").unwrap_or_default(),
                    message: str_field(&v, "message").unwrap_or_default(),
                }]
            }
            other => vec![Event::Ignored {
                event_type: other.to_string(),
            }],
        })
    }

    /// kirocc `toolUseAccumulator.update`.
    fn tool_use(&mut self, v: &Value) -> Result<Vec<Event>, EventError> {
        let mut out = Vec::new();
        let mut current_id = str_field(v, "toolUseId").unwrap_or_default();
        let has_name = v.get("name").is_some();
        let is_new = if !current_id.is_empty() && current_id != self.tool.id {
            true
        } else if current_id.is_empty() && self.tool.id.is_empty() && has_name {
            current_id = uuid::Uuid::new_v4().to_string();
            true
        } else {
            false
        };
        if is_new {
            if !self.tool.id.is_empty() {
                out.push(self.tool.take());
            }
            self.tool.id = current_id;
            self.tool.name.clear();
            self.tool.input.clear();
        }
        if let Some(name) = str_field(v, "name") {
            self.tool.name = name;
        }
        match v.get("input") {
            Some(Value::String(s)) => self.tool.input.push_str(s),
            Some(other) if !other.is_null() => self.tool.input = other.to_string(),
            _ => {}
        }
        if self.tool.input.len() > MAX_TOOL_INPUT_BYTES {
            return Err(EventError::ToolInputTooLarge {
                tool_use_id: self.tool.id.clone(),
                max: MAX_TOOL_INPUT_BYTES,
            });
        }
        if v.get("stop").and_then(Value::as_bool) == Some(true) {
            out.push(self.tool.take());
        }
        Ok(out)
    }

    /// Flush an in-flight tool call at end of stream (kirocc `flush`).
    pub fn finish(&mut self) -> Option<Event> {
        if self.tool.id.is_empty() {
            None
        } else {
            Some(self.tool.take())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiro::Event;

    fn decode_all(bytes: &[u8]) -> Vec<Frame> {
        let mut d = FrameDecoder::new();
        d.push(bytes);
        let mut out = Vec::new();
        while let Some(f) = d.next_frame().unwrap() {
            out.push(f);
        }
        d.finish().unwrap();
        out
    }

    // kirocc TestReadFrame / TestParseStream_MultipleFrames
    #[test]
    fn round_trips_frames_and_splits_across_pushes() {
        let a = encode_event_frame("assistantResponseEvent", br#"{"content":"pass"}"#);
        let b = encode_event_frame("assistantResponseEvent", br#"{"content":"word"}"#);
        let joined = [a.clone(), b.clone()].concat();
        let frames = decode_all(&joined);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].event_type(), Some("assistantResponseEvent"));
        assert_eq!(frames[1].payload, br#"{"content":"word"}"#);

        // Byte-at-a-time delivery yields the same frames.
        let mut d = FrameDecoder::new();
        let mut got = Vec::new();
        for byte in joined.iter() {
            d.push(std::slice::from_ref(byte));
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f);
            }
        }
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn rejects_bad_prelude_crc_and_oversized_frames() {
        let mut bad = encode_event_frame("assistantResponseEvent", b"{}");
        bad[8] ^= 0xff;
        let mut d = FrameDecoder::new();
        d.push(&bad);
        assert!(matches!(d.next_frame(), Err(FrameError::PreludeCrc { .. })));

        let mut bad = encode_event_frame("assistantResponseEvent", b"{}");
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        let mut d = FrameDecoder::new();
        d.push(&bad);
        assert!(matches!(d.next_frame(), Err(FrameError::MessageCrc { .. })));

        let mut huge = vec![0u8; 12];
        huge[..4].copy_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
        huge[4..8].copy_from_slice(&0u32.to_be_bytes());
        let crc = crc32fast::hash(&huge[..8]);
        huge[8..12].copy_from_slice(&crc.to_be_bytes());
        let mut d = FrameDecoder::new();
        d.push(&huge);
        assert!(matches!(d.next_frame(), Err(FrameError::TooLarge { .. })));
    }

    #[test]
    fn truncated_stream_is_an_error_but_clean_end_is_not() {
        let frame = encode_event_frame("assistantResponseEvent", b"{}");
        let mut d = FrameDecoder::new();
        d.push(&frame[..frame.len() - 3]);
        assert!(d.next_frame().unwrap().is_none());
        assert!(matches!(d.finish(), Err(FrameError::Truncated { .. })));
        let mut d = FrameDecoder::new();
        d.push(&frame);
        assert!(d.next_frame().unwrap().is_some());
        assert!(d.finish().is_ok());
    }

    // kirocc TestParseStream_VariousHeaderTypes
    #[test]
    fn parses_every_header_type() {
        let mut headers = Vec::new();
        push_header(
            &mut headers,
            ":event-type",
            &HeaderValue::String("x".into()),
        );
        push_header(&mut headers, "t", &HeaderValue::Bool(true));
        push_header(&mut headers, "f", &HeaderValue::Bool(false));
        push_header(&mut headers, "b", &HeaderValue::Byte(7));
        push_header(&mut headers, "s", &HeaderValue::Short(-2));
        push_header(&mut headers, "i", &HeaderValue::Int(70000));
        push_header(&mut headers, "l", &HeaderValue::Long(-5));
        push_header(&mut headers, "by", &HeaderValue::Bytes(vec![1, 2]));
        push_header(
            &mut headers,
            "ts",
            &HeaderValue::Timestamp(1_700_000_000_000),
        );
        push_header(&mut headers, "u", &HeaderValue::Uuid([9u8; 16]));
        let bytes = encode_frame(&headers, b"{}");
        let frames = decode_all(&bytes);
        assert_eq!(frames[0].headers.len(), 10);
        assert_eq!(frames[0].headers[5].1, HeaderValue::Int(70000));
        assert_eq!(frames[0].headers[9].1, HeaderValue::Uuid([9u8; 16]));
    }

    fn events(frames: &[Vec<u8>]) -> Vec<Event> {
        let mut d = FrameDecoder::new();
        let mut p = EventParser::new();
        let mut out = Vec::new();
        for f in frames {
            d.push(f);
            while let Some(frame) = d.next_frame().unwrap() {
                out.extend(p.parse(&frame).unwrap());
            }
        }
        out.extend(p.finish());
        out
    }

    // kirocc TestParseStream_SingleEvents, TestParseStream_ExceptionFrame
    #[test]
    fn decodes_each_event_type() {
        let got = events(&[
            encode_event_frame("assistantResponseEvent", br#"{"content":"hi"}"#),
            encode_event_frame("reasoningContentEvent", br#"{"text":"think","signature":"sig"}"#),
            encode_event_frame("metadataEvent", br#"{"tokenUsage":{"uncachedInputTokens":10,"outputTokens":5,"totalTokens":15,"cacheReadInputTokens":100,"cacheWriteInputTokens":20}}"#),
            encode_event_frame("meteringEvent", br#"{"usage":0.5,"inputTokens":1,"outputTokens":2}"#),
            encode_event_frame("invalidStateEvent", br#"{"reason":"STALE_CONVERSATION","message":"stale"}"#),
            encode_event_frame("followupPromptEvent", br#"{}"#),
            encode_event_frame("somethingNew", br#"{"x":1}"#),
            encode_exception_frame("ThrottlingException", br#"{"message":"slow down"}"#),
        ]);
        assert_eq!(
            got[0],
            Event::AssistantResponse {
                content: "hi".into()
            }
        );
        assert_eq!(
            got[1],
            Event::ReasoningContent {
                text: "think".into(),
                signature: Some("sig".into()),
                redacted_content: None
            }
        );
        assert_eq!(
            got[2],
            Event::Metadata {
                uncached_input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
                cache_read_input_tokens: 100,
                cache_write_input_tokens: 20
            }
        );
        assert_eq!(
            got[3],
            Event::Metering {
                credits: 0.5,
                input_tokens: 1,
                output_tokens: 2
            }
        );
        assert_eq!(
            got[4],
            Event::InvalidState {
                reason: "STALE_CONVERSATION".into(),
                message: "stale".into()
            }
        );
        assert_eq!(
            got[5],
            Event::Ignored {
                event_type: "followupPromptEvent".into()
            }
        );
        assert_eq!(
            got[6],
            Event::Ignored {
                event_type: "somethingNew".into()
            }
        );
        assert_eq!(
            got[7],
            Event::Exception {
                exception_type: "ThrottlingException".into(),
                message: "slow down".into()
            }
        );
    }

    // kirocc TestParseStream_ToolUseEvent, _MissingStop, TestToolUseAccumulator
    #[test]
    fn accumulates_tool_use_fragments() {
        let got = events(&[
            encode_event_frame(
                "toolUseEvent",
                br#"{"toolUseId":"t1","name":"Read","input":"{\"pa"}"#,
            ),
            encode_event_frame(
                "toolUseEvent",
                br#"{"toolUseId":"t1","input":"th\":\"a\"}"}"#,
            ),
            encode_event_frame("toolUseEvent", br#"{"toolUseId":"t1","stop":true}"#),
            // Object-form input replaces the buffer.
            encode_event_frame(
                "toolUseEvent",
                br#"{"toolUseId":"t2","name":"Bash","input":{"cmd":"ls"},"stop":true}"#,
            ),
            // Missing stop: a new id flushes the previous call.
            encode_event_frame(
                "toolUseEvent",
                br#"{"toolUseId":"t3","name":"Grep","input":"{}"}"#,
            ),
            encode_event_frame(
                "toolUseEvent",
                br#"{"toolUseId":"t4","name":"Glob","input":"{}"}"#,
            ),
        ]);
        assert_eq!(
            got[0],
            Event::ToolUse {
                tool_use_id: "t1".into(),
                name: "Read".into(),
                input: r#"{"path":"a"}"#.into()
            }
        );
        assert_eq!(
            got[1],
            Event::ToolUse {
                tool_use_id: "t2".into(),
                name: "Bash".into(),
                input: r#"{"cmd":"ls"}"#.into()
            }
        );
        assert_eq!(
            got[2],
            Event::ToolUse {
                tool_use_id: "t3".into(),
                name: "Grep".into(),
                input: "{}".into()
            }
        );
        assert_eq!(
            got[3],
            Event::ToolUse {
                tool_use_id: "t4".into(),
                name: "Glob".into(),
                input: "{}".into()
            },
            "EOF flushes the in-flight call"
        );
    }

    #[test]
    fn tool_input_is_capped() {
        let mut p = EventParser::new();
        let mut d = FrameDecoder::new();
        let chunk = "x".repeat(1024 * 1024);
        let payload = format!(r#"{{"toolUseId":"t1","name":"Read","input":"{chunk}"}}"#);
        let frame = encode_event_frame("toolUseEvent", payload.as_bytes());
        for _ in 0..16 {
            d.push(&frame);
            let f = d.next_frame().unwrap().unwrap();
            p.parse(&f).unwrap();
        }
        d.push(&frame);
        let f = d.next_frame().unwrap().unwrap();
        assert!(matches!(
            p.parse(&f),
            Err(EventError::ToolInputTooLarge { .. })
        ));
    }
}

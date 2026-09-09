#![no_main]
use arbitrary::Arbitrary;
use kiro_trust_protocol::eventstream::{
    EventParser, FrameDecoder, encode_event_frame, encode_exception_frame,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

/// The six `event-type` literals `EventParser::parse` dispatches on
/// (`eventstream.rs:368-424`), an `Exception` variant for the separate
/// `:message-type: exception` branch, and `Other` as the free-form escape
/// hatch that keeps the unknown-type fallthrough reachable (fix-1
/// Important 3). Each known variant carries the exact fields its branch
/// reads, so the payload is always a JSON object with the right keys
/// rather than unconstrained bytes.
#[derive(Arbitrary, Debug)]
enum GenEvent {
    AssistantResponse {
        content: String,
    },
    ReasoningContent {
        text: String,
        signature: Option<String>,
        redacted_content: Option<String>,
    },
    ToolUse {
        id: Option<u8>,
        name: Option<String>,
        input_object: bool,
        input_string: Option<String>,
        stop: Option<bool>,
    },
    Metadata {
        uncached_input_tokens: u32,
        output_tokens: u32,
        total_tokens: u32,
        cache_read_input_tokens: u32,
        cache_write_input_tokens: u32,
    },
    Metering {
        usage: f64,
        input_tokens: u32,
        output_tokens: u32,
    },
    InvalidState {
        reason: String,
        message: String,
    },
    Exception {
        exception_type: String,
        message: String,
    },
    Other {
        event_type: String,
        payload: Vec<u8>,
    },
}

fn build(ev: GenEvent) -> Vec<u8> {
    match ev {
        GenEvent::AssistantResponse { content } => {
            let mut m = Map::new();
            m.insert("content".into(), Value::String(content));
            encode_event_frame("assistantResponseEvent", &to_bytes(m))
        }
        GenEvent::ReasoningContent {
            text,
            signature,
            redacted_content,
        } => {
            let mut m = Map::new();
            m.insert("text".into(), Value::String(text));
            if let Some(s) = signature {
                m.insert("signature".into(), Value::String(s));
            }
            if let Some(r) = redacted_content {
                m.insert("redactedContent".into(), Value::String(r));
            }
            encode_event_frame("reasoningContentEvent", &to_bytes(m))
        }
        GenEvent::ToolUse {
            id,
            name,
            input_object,
            input_string,
            stop,
        } => {
            let mut m = Map::new();
            if let Some(id) = id {
                m.insert("toolUseId".into(), Value::String(format!("t{id}")));
            }
            if let Some(n) = name {
                m.insert("name".into(), Value::String(n));
            }
            if input_object {
                m.insert("input".into(), serde_json::json!({"k": 1}));
            } else if let Some(s) = input_string {
                m.insert("input".into(), Value::String(s));
            }
            if let Some(s) = stop {
                m.insert("stop".into(), Value::Bool(s));
            }
            encode_event_frame("toolUseEvent", &to_bytes(m))
        }
        GenEvent::Metadata {
            uncached_input_tokens,
            output_tokens,
            total_tokens,
            cache_read_input_tokens,
            cache_write_input_tokens,
        } => {
            let mut tu = Map::new();
            tu.insert(
                "uncachedInputTokens".into(),
                Value::Number(uncached_input_tokens.into()),
            );
            tu.insert("outputTokens".into(), Value::Number(output_tokens.into()));
            tu.insert("totalTokens".into(), Value::Number(total_tokens.into()));
            tu.insert(
                "cacheReadInputTokens".into(),
                Value::Number(cache_read_input_tokens.into()),
            );
            tu.insert(
                "cacheWriteInputTokens".into(),
                Value::Number(cache_write_input_tokens.into()),
            );
            let mut m = Map::new();
            m.insert("tokenUsage".into(), Value::Object(tu));
            encode_event_frame("metadataEvent", &to_bytes(m))
        }
        GenEvent::Metering {
            usage,
            input_tokens,
            output_tokens,
        } => {
            let mut m = Map::new();
            // Wire JSON (RFC 8259) has no NaN/Infinity; clamp rather than
            // let a non-finite float make serialization fail below, which
            // would be a fuzz-target bug, not a protocol one.
            let usage = serde_json::Number::from_f64(usage).unwrap_or_else(|| 0.into());
            m.insert("usage".into(), Value::Number(usage));
            m.insert("inputTokens".into(), Value::Number(input_tokens.into()));
            m.insert("outputTokens".into(), Value::Number(output_tokens.into()));
            encode_event_frame("meteringEvent", &to_bytes(m))
        }
        GenEvent::InvalidState { reason, message } => {
            let mut m = Map::new();
            m.insert("reason".into(), Value::String(reason));
            m.insert("message".into(), Value::String(message));
            encode_event_frame("invalidStateEvent", &to_bytes(m))
        }
        GenEvent::Exception {
            exception_type,
            message,
        } => {
            let exception_type: String = exception_type.chars().take(50).collect();
            let mut m = Map::new();
            m.insert("message".into(), Value::String(message));
            encode_exception_frame(&exception_type, &to_bytes(m))
        }
        GenEvent::Other {
            event_type,
            mut payload,
        } => {
            let event_type: String = event_type.chars().take(50).collect();
            payload.truncate(2048);
            encode_event_frame(&event_type, &payload)
        }
    }
}

fn to_bytes(m: Map<String, Value>) -> Vec<u8> {
    serde_json::to_vec(&Value::Object(m)).expect("generated payload serializes")
}

fuzz_target!(|events: Vec<GenEvent>| {
    let mut d = FrameDecoder::new();
    let mut p = EventParser::new();
    for ev in events.into_iter().take(64) {
        d.push(&build(ev));
        while let Ok(Some(f)) = d.next_frame() {
            let _ = p.parse(&f);
        }
    }
    let _ = p.finish();
});

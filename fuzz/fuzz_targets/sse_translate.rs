#![no_main]
use arbitrary::Arbitrary;
use kiro_trust_protocol::anthropic::StreamEvent;
use kiro_trust_protocol::kiro::Event;
use kiro_trust_protocol::translate::response::{ResponseOptions, ResponseTranslator};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Ev {
    Text(String),
    Reason(String, Option<String>, Option<String>),
    Tool(u8, String, String),
    Meta(u32, u32, u32, u32),
    Metering(f64, u32, u32),
    Invalid(String, String),
    Exception(String, String),
    Ignored(String),
}

#[derive(Arbitrary, Debug)]
struct Input {
    stop_sequences: Vec<String>,
    max_tokens: u16,
    events: Vec<Ev>,
}

fuzz_target!(|input: Input| {
    let mut t = ResponseTranslator::new(ResponseOptions {
        model: "m".into(),
        message_id: "msg_fuzz".into(),
        stop_sequences: input.stop_sequences.into_iter().take(4).collect(),
        max_tokens: input.max_tokens as u32,
        tool_names: Default::default(),
        estimated_input_tokens: 1,
    });
    let mut open: Option<u32> = None;
    let mut last_index: i64 = -1;
    let mut check = |evs: Vec<StreamEvent>| {
        for e in evs {
            match e {
                StreamEvent::ContentBlockStart { index, .. } => {
                    assert!(open.is_none(), "block opened while another is open");
                    assert!(index as i64 > last_index, "indices must increase");
                    last_index = index as i64;
                    open = Some(index);
                }
                StreamEvent::ContentBlockDelta { index, .. } => assert_eq!(open, Some(index)),
                StreamEvent::ContentBlockStop { index } => {
                    assert_eq!(open, Some(index));
                    open = None;
                }
                StreamEvent::MessageDelta { .. } => {
                    assert!(open.is_none(), "message_delta with an open block")
                }
                _ => {}
            }
        }
    };
    for ev in input.events.into_iter().take(128) {
        let ev = match ev {
            Ev::Text(c) => Event::AssistantResponse { content: c },
            Ev::Reason(t, s, r) => Event::ReasoningContent {
                text: t,
                signature: s,
                redacted_content: r,
            },
            Ev::Tool(id, n, i) => Event::ToolUse {
                tool_use_id: format!("t{id}"),
                name: n,
                input: i,
            },
            Ev::Meta(a, b, c, d) => Event::Metadata {
                uncached_input_tokens: a as u64,
                output_tokens: b as u64,
                // Widen before adding: `a + b` as u32 can overflow (this
                // field is otherwise unused by the translator, spec 5.4).
                total_tokens: u64::from(a) + u64::from(b),
                cache_read_input_tokens: c as u64,
                cache_write_input_tokens: d as u64,
            },
            Ev::Metering(c, i, o) => Event::Metering {
                credits: c,
                input_tokens: i as u64,
                output_tokens: o as u64,
            },
            Ev::Invalid(r, m) => Event::InvalidState {
                reason: r,
                message: m,
            },
            Ev::Exception(t, m) => Event::Exception {
                exception_type: t,
                message: m,
            },
            Ev::Ignored(t) => Event::Ignored { event_type: t },
        };
        check(t.push(&ev));
    }
    check(t.finish());
    assert!(t.finish().is_empty() || t.failure().is_some());
    let _ = t.into_message();
});

#![no_main]
use arbitrary::Arbitrary;
use kiro_trust_protocol::anthropic::StreamEvent;
use kiro_trust_protocol::kiro::Event;
use kiro_trust_protocol::sse;
use kiro_trust_protocol::translate::response::{ResponseOptions, ResponseTranslator};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Draws from `Input::tool_names`' keys so the short-name remapping at
/// `response.rs:456-461` is actually exercised (fix-1 minor 4) instead of
/// an independently-generated name almost never matching a map key.
#[derive(Arbitrary, Debug)]
enum ToolName {
    Known(u8),
    Custom(String),
}

#[derive(Arbitrary, Debug)]
enum Ev {
    Text(String),
    Reason(String, Option<String>, Option<String>),
    Tool(u8, ToolName, String),
    // u64 fields (was u32): keeps `saturating_add` at response.rs:502 from
    // sitting far below its actual saturation boundary (fix-1 minor 5).
    Meta(u64, u64, u64, u64),
    Metering(f64, u32, u32),
    Invalid(String, String),
    Exception(String, String),
    Ignored(String),
}

#[derive(Arbitrary, Debug)]
struct StopPick {
    offset: u8,
    len: u8,
}

#[derive(Arbitrary, Debug)]
struct Input {
    stop_picks: Vec<StopPick>,
    max_tokens: u16,
    tool_names: Vec<(String, String)>,
    events: Vec<Ev>,
}

/// Stop sequences drawn as substrings of the text this run will actually
/// generate (falling back to a tiny fixed alphabet when there is no text
/// yet), so `apply_stop_filter`'s hit branch (`response.rs:190-196`) is
/// reachable instead of needing an unconstrained string to match generated
/// text exactly by chance (fix-1 minor 6).
fn derive_stop_sequences(picks: Vec<StopPick>, sample: &str) -> Vec<String> {
    const ALPHABET: [&str; 4] = ["\n", "stop", "a", "STOP"];
    let chars: Vec<char> = sample.chars().collect();
    picks
        .into_iter()
        .take(4)
        .map(|p| {
            if chars.is_empty() {
                ALPHABET[p.offset as usize % ALPHABET.len()].to_string()
            } else {
                let start = p.offset as usize % chars.len();
                let max_len = chars.len() - start;
                let len = (p.len as usize % max_len) + 1;
                chars[start..start + len].iter().collect()
            }
        })
        .collect()
}

fuzz_target!(|input: Input| {
    let events: Vec<Ev> = input.events.into_iter().take(128).collect();
    let sample: String = events
        .iter()
        .filter_map(|e| match e {
            Ev::Text(c) => Some(c.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
        .chars()
        .take(300)
        .collect();
    let stop_sequences = derive_stop_sequences(input.stop_picks, &sample);

    let tool_names: HashMap<String, String> = input
        .tool_names
        .into_iter()
        .take(8)
        .map(|(k, v)| {
            (
                k.chars().take(20).collect::<String>(),
                v.chars().take(20).collect::<String>(),
            )
        })
        .collect();
    let tool_name_keys: Vec<String> = tool_names.keys().cloned().collect();

    let mut t = ResponseTranslator::new(ResponseOptions {
        model: "m".into(),
        message_id: "msg_fuzz".into(),
        stop_sequences,
        max_tokens: input.max_tokens as u32,
        tool_names,
        estimated_input_tokens: 1,
    });
    let mut open: Option<u32> = None;
    let mut last_index: i64 = -1;
    let mut all: Vec<StreamEvent> = Vec::new();
    {
        let mut check = |evs: Vec<StreamEvent>| {
            for e in &evs {
                match e {
                    StreamEvent::ContentBlockStart { index, .. } => {
                        assert!(open.is_none(), "block opened while another is open");
                        assert!(*index as i64 > last_index, "indices must increase");
                        last_index = *index as i64;
                        open = Some(*index);
                    }
                    StreamEvent::ContentBlockDelta { index, .. } => {
                        assert_eq!(open, Some(*index))
                    }
                    StreamEvent::ContentBlockStop { index } => {
                        assert_eq!(open, Some(*index));
                        open = None;
                    }
                    StreamEvent::MessageDelta { .. } => {
                        assert!(open.is_none(), "message_delta with an open block")
                    }
                    _ => {}
                }
                // Run the SSE writer over arbitrary text, control
                // characters, and embedded newlines (fix-1 Important 2).
                let _ = sse::encode(e);
            }
            all.extend(evs);
        };
        for ev in events {
            let ev = match ev {
                Ev::Text(c) => Event::AssistantResponse { content: c },
                Ev::Reason(t, s, r) => Event::ReasoningContent {
                    text: t,
                    signature: s,
                    redacted_content: r,
                },
                Ev::Tool(id, name, i) => {
                    let name = match name {
                        ToolName::Known(idx) => tool_name_keys
                            .get(idx as usize % tool_name_keys.len().max(1))
                            .cloned()
                            .unwrap_or_else(|| "unknown_tool".to_string()),
                        ToolName::Custom(n) => n,
                    };
                    Event::ToolUse {
                        tool_use_id: format!("t{id}"),
                        name,
                        input: i,
                    }
                }
                Ev::Meta(a, b, c, d) => Event::Metadata {
                    uncached_input_tokens: a,
                    output_tokens: b,
                    total_tokens: a.saturating_add(b),
                    cache_read_input_tokens: c,
                    cache_write_input_tokens: d,
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
    }

    // finish() being idempotent doesn't by itself prove push() respects
    // that; assert the real property (fix-1 minor 2).
    assert!(
        t.push(&Event::Ignored {
            event_type: "post-finish-probe".into()
        })
        .is_empty(),
        "push after finish must return nothing"
    );

    // MessageStart opens the stream, MessageStop closes it, and this
    // harness never pushes anything into `all` after finish() (fix-1
    // minor 3).
    assert!(
        matches!(all.first(), Some(StreamEvent::MessageStart { .. })),
        "stream must start with MessageStart"
    );
    let stop_positions: Vec<usize> = all
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, StreamEvent::MessageStop))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(stop_positions.len(), 1, "exactly one MessageStop");
    assert_eq!(stop_positions[0], all.len() - 1, "MessageStop must be last");

    let _ = t.into_message();
});

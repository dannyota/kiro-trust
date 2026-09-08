//! Server-sent events serialization (spec 5.4).

use crate::anthropic::StreamEvent;

pub const KEEPALIVE: &str = ": keep-alive\n\n";

pub fn encode(event: &StreamEvent) -> String {
    let data = serde_json::to_string(event).expect("stream events serialize");
    format!("event: {}\ndata: {}\n\n", event.event_name(), data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{Delta, StreamEvent};

    #[test]
    fn encodes_event_and_data_lines() {
        let ev = StreamEvent::ContentBlockDelta {
            index: 0,
            delta: Delta::TextDelta {
                text: "a\nb".into(),
            },
        };
        assert_eq!(
            encode(&ev),
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"a\\nb\"}}\n\n"
        );
        assert_eq!(
            encode(&StreamEvent::MessageStop),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        assert_eq!(KEEPALIVE, ": keep-alive\n\n");
    }
}

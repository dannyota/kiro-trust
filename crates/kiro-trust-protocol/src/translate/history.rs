//! Kiro history entries. Transcribed from kirocc internal/reqconv/history.go
//! and build_payload.go (`placeSystemPrompt`). Thinking blocks are dropped
//! from history; redacted-blob replay is a GPT-only path and is not ported.

use super::content::{
    extract_text, extract_tool_results, extract_tool_use_ids, extract_tool_uses,
    reorder_tool_results,
};
use super::tool_names::ToolNameMap;
use crate::anthropic::{Message, Role};
use crate::kiro::{
    AssistantResponseMessage, HistoryEntry, HistoryUserInputMessage, ORIGIN_KIRO_CLI,
    UserInputMessageContext,
};
use uuid::Uuid;

pub const SYNTHETIC_ACK: &str = "I will fully incorporate this information when generating my responses, and explicitly acknowledge relevant parts of the summary when answering questions.";

fn v5(seed: &str) -> String {
    Uuid::new_v5(&Uuid::NAMESPACE_URL, seed.as_bytes()).to_string()
}

pub fn build_history(msgs: &[Message], names: &mut ToolNameMap) -> Vec<HistoryEntry> {
    let mut history = Vec::with_capacity(msgs.len());
    for (i, m) in msgs.iter().enumerate() {
        match m.role {
            Role::User | Role::Other => {
                let mut results = extract_tool_results(&m.content);
                if results.len() > 1 && i > 0 && msgs[i - 1].role == Role::Assistant {
                    results =
                        reorder_tool_results(results, &extract_tool_use_ids(&msgs[i - 1].content));
                }
                let context = (!results.is_empty()).then(|| UserInputMessageContext {
                    tool_results: results,
                    ..Default::default()
                });
                history.push(HistoryEntry::UserInputMessage(HistoryUserInputMessage {
                    content: extract_text(&m.content),
                    model_id: None,
                    origin: Some(ORIGIN_KIRO_CLI),
                    user_input_message_context: context,
                    // Populated by the image-translation slice once the
                    // `history_image_is_accepted` live gate (spec 5.3 step 6)
                    // has passed; empty until then.
                    images: vec![],
                    cache_point: None,
                }));
            }
            Role::Assistant => {
                let content = extract_text(&m.content);
                let mut tool_uses = extract_tool_uses(&m.content);
                for t in &mut tool_uses {
                    t.name = names.shorten(&t.name);
                }
                let mut seed = format!("assistant-msg:{content}");
                for t in &tool_uses {
                    seed.push(':');
                    seed.push_str(&t.tool_use_id);
                }
                history.push(HistoryEntry::AssistantResponseMessage(
                    AssistantResponseMessage {
                        message_id: Some(v5(&seed)),
                        content,
                        tool_uses,
                        cache_point: None,
                    },
                ));
            }
        }
    }
    history
}

/// The system prompt travels as a leading user/assistant pair in history.
pub fn place_system_prompt(system: &str, history: Vec<HistoryEntry>) -> Vec<HistoryEntry> {
    if system.is_empty() {
        return history;
    }
    let mut out = Vec::with_capacity(history.len() + 2);
    out.push(HistoryEntry::UserInputMessage(HistoryUserInputMessage {
        content: system.to_string(),
        model_id: None,
        origin: Some(ORIGIN_KIRO_CLI),
        user_input_message_context: None,
        // The system prompt never carries an image (spec 5.3 step 4).
        images: vec![],
        cache_point: None,
    }));
    out.push(HistoryEntry::AssistantResponseMessage(
        AssistantResponseMessage {
            message_id: Some(v5(&format!("synthetic-ack:{SYNTHETIC_ACK}"))),
            content: SYNTHETIC_ACK.to_string(),
            tool_uses: vec![],
            cache_point: None,
        },
    ));
    out.extend(history);
    out
}

//! Deterministic, offline `count_tokens` estimate (spec 5.7).

use crate::anthropic::{MessageContent, Request, ToolResultContent};

pub fn count_tokens(req: &Request) -> u64 {
    let mut bytes = req.system_text().len();
    for m in &req.messages {
        match &m.content {
            MessageContent::Text(t) => bytes += t.len(),
            MessageContent::Blocks(blocks) => {
                for b in blocks {
                    if let Some(t) = &b.text {
                        bytes += t.len();
                    }
                    if let Some(t) = &b.thinking {
                        bytes += t.len();
                    }
                    if let Some(input) = &b.input {
                        bytes += input.to_string().len();
                    }
                    match &b.content {
                        Some(ToolResultContent::Text(t)) => bytes += t.len(),
                        Some(ToolResultContent::Blocks(inner)) => {
                            bytes += inner
                                .iter()
                                .filter_map(|c| c.text.as_ref())
                                .map(String::len)
                                .sum::<usize>();
                        }
                        None => {}
                    }
                }
            }
        }
    }
    for t in &req.tools {
        bytes += serde_json::to_string(t).map(|s| s.len()).unwrap_or(0);
    }
    bytes.div_ceil(4) as u64 + 3 * req.messages.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::Request;
    use serde_json::json;

    #[test]
    fn estimate_is_deterministic_and_counts_every_text_source() {
        let r: Request = serde_json::from_value(json!({"model": "m", "max_tokens": 1, "system": "abcd",
            "tools": [{"name": "T", "description": "dddd", "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "abcdefgh"},
                         {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "T", "input": {"k": "vvvv"}}]},
                         {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "rrrr"}]}]})).unwrap();
        let n = count_tokens(&r);
        assert_eq!(n, count_tokens(&r));
        assert!(
            n >= 3 * 3 + (4 + 8 + 4) / 4,
            "at least the per-message constant plus visible text"
        );
        let empty: Request = serde_json::from_value(
            json!({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": ""}]}),
        )
        .unwrap();
        assert_eq!(count_tokens(&empty), 3);
    }
}

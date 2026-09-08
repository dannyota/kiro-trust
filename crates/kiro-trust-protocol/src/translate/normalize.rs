//! Message normalization before history building. Transcribed from kirocc
//! internal/reqconv/message_normalizer.go, minus the tool-search expansion.

use super::content::{extract_text, extract_tool_result_text};
use crate::anthropic::{ContentBlock, Message, MessageContent, Role};
use std::collections::HashSet;

pub const SYNTHETIC_EMPTY: &str = "(empty)";
pub const SYNTHETIC_CONTINUE: &str = "Continue";

pub fn normalize_messages(msgs: &[Message], has_tools: bool) -> Vec<Message> {
    let msgs = if has_tools {
        textualize_orphan_tool_results(msgs)
    } else {
        textualize_all_tool_content(msgs)
    };
    let msgs = normalize_roles(msgs);
    let msgs = merge_adjacent_same_role(msgs);
    let msgs = ensure_starts_with_user(msgs);
    ensure_alternating_roles(msgs)
}

fn text_block(text: String) -> ContentBlock {
    ContentBlock {
        kind: "text".into(),
        text: Some(text),
        ..Default::default()
    }
}

fn textualize_all_tool_content(msgs: &[Message]) -> Vec<Message> {
    msgs.iter()
        .map(|m| match &m.content {
            MessageContent::Text(_) => m.clone(),
            MessageContent::Blocks(blocks) => Message {
                role: m.role,
                content: MessageContent::Blocks(
                    blocks
                        .iter()
                        .map(|b| {
                            if b.is_tool_use() {
                                let input = b
                                    .input
                                    .as_ref()
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "null".into());
                                text_block(format!(
                                    "[Tool: {} ({})]\n{}",
                                    b.name.as_deref().unwrap_or(""),
                                    b.id.as_deref().unwrap_or(""),
                                    input
                                ))
                            } else if b.is_tool_result() {
                                text_block(format!(
                                    "[Tool Result ({})]\n{}",
                                    b.tool_use_id.as_deref().unwrap_or(""),
                                    extract_tool_result_text(b)
                                ))
                            } else {
                                b.clone()
                            }
                        })
                        .collect(),
                ),
            },
        })
        .collect()
}

fn textualize_orphan_tool_results(msgs: &[Message]) -> Vec<Message> {
    let mut out = Vec::with_capacity(msgs.len());
    for (i, m) in msgs.iter().enumerate() {
        let MessageContent::Blocks(blocks) = &m.content else {
            out.push(m.clone());
            continue;
        };
        if m.role != Role::User {
            out.push(m.clone());
            continue;
        }
        let mut ids: HashSet<&str> = HashSet::new();
        if i > 0
            && msgs[i - 1].role == Role::Assistant
            && let MessageContent::Blocks(prev) = &msgs[i - 1].content
        {
            ids.extend(
                prev.iter()
                    .filter(|b| b.is_tool_use())
                    .filter_map(|b| b.id.as_deref()),
            );
        }
        let new_blocks = blocks
            .iter()
            .map(|b| {
                if b.is_tool_result() && !ids.contains(b.tool_use_id.as_deref().unwrap_or("")) {
                    text_block(format!(
                        "[Tool Result ({})]\n{}",
                        b.tool_use_id.as_deref().unwrap_or(""),
                        extract_tool_result_text(b)
                    ))
                } else {
                    b.clone()
                }
            })
            .collect();
        out.push(Message {
            role: m.role,
            content: MessageContent::Blocks(new_blocks),
        });
    }
    out
}

fn is_plain_text(c: &MessageContent) -> bool {
    match c {
        MessageContent::Text(_) => true,
        MessageContent::Blocks(b) => b.iter().all(|b| b.kind == "text"),
    }
}

fn merge_adjacent_same_role(msgs: Vec<Message>) -> Vec<Message> {
    let mut out: Vec<Message> = Vec::with_capacity(msgs.len());
    let mut i = 0;
    while i < msgs.len() {
        let mut j = i + 1;
        if is_plain_text(&msgs[i].content) {
            while j < msgs.len() && msgs[j].role == msgs[i].role && is_plain_text(&msgs[j].content)
            {
                j += 1;
            }
        }
        if j == i + 1 {
            out.push(msgs[i].clone());
        } else {
            let joined = msgs[i..j]
                .iter()
                .map(|m| extract_text(&m.content))
                .collect::<Vec<_>>()
                .join("\n");
            out.push(Message {
                role: msgs[i].role,
                content: MessageContent::Text(joined),
            });
        }
        i = j;
    }
    out
}

fn normalize_roles(mut msgs: Vec<Message>) -> Vec<Message> {
    for m in &mut msgs {
        if m.role == Role::Other {
            m.role = Role::User;
        }
    }
    msgs
}

fn ensure_starts_with_user(mut msgs: Vec<Message>) -> Vec<Message> {
    if msgs.first().is_some_and(|m| m.role != Role::User) {
        msgs.insert(
            0,
            Message {
                role: Role::User,
                content: MessageContent::Text(SYNTHETIC_EMPTY.into()),
            },
        );
    }
    msgs
}

fn ensure_alternating_roles(msgs: Vec<Message>) -> Vec<Message> {
    let mut out: Vec<Message> = Vec::with_capacity(msgs.len());
    for m in msgs {
        if let Some(last) = out.last()
            && last.role == m.role
        {
            let opposite = if m.role == Role::Assistant {
                Role::User
            } else {
                Role::Assistant
            };
            out.push(Message {
                role: opposite,
                content: MessageContent::Text(SYNTHETIC_EMPTY.into()),
            });
        }
        out.push(m);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{Message, MessageContent, Role};
    use serde_json::json;

    fn msgs(v: serde_json::Value) -> Vec<Message> {
        serde_json::from_value(v).unwrap()
    }
    fn text(m: &Message) -> String {
        crate::translate::content::extract_text(&m.content)
    }

    // kirocc TestNormalize_FullPipeline, TestStep2_MergeAdjacentSameRole, TestStep5_EnsureAlternating,
    // TestStep3_EnsureStartsWithUser, TestStep4_NormalizeRoles, TestStep2_DoesNotMergeStructuredContent
    #[test]
    fn merges_text_runs_and_fixes_alternation() {
        let out = normalize_messages(
            &msgs(json!([
                {"role": "assistant", "content": "first"},
                {"role": "developer", "content": "a"},
                {"role": "user", "content": [{"type": "text", "text": "b"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "x", "name": "T", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x", "content": "r"}]},
                {"role": "user", "content": "c"}
            ])),
            true,
        );
        let roles: Vec<Role> = out.iter().map(|m| m.role).collect();
        assert_eq!(
            roles,
            vec![
                Role::User,
                Role::Assistant,
                Role::User,
                Role::Assistant,
                Role::User,
                Role::Assistant,
                Role::User
            ]
        );
        assert_eq!(
            text(&out[0]),
            SYNTHETIC_EMPTY,
            "conversation must start with a user message"
        );
        assert_eq!(text(&out[1]), "first");
        assert_eq!(
            text(&out[2]),
            "a\nb",
            "developer role becomes user and merges with the text run"
        );
        assert!(
            matches!(out[3].content, MessageContent::Blocks(_)),
            "tool_use stays structured"
        );
        assert!(
            matches!(out[4].content, MessageContent::Blocks(_)),
            "matched tool_result is not merged"
        );
        assert_eq!(
            text(&out[5]),
            SYNTHETIC_EMPTY,
            "alternation inserts an assistant between two user messages"
        );
        assert_eq!(text(&out[6]), "c");
    }

    // kirocc TestStep1a_TextualizeAllToolContent, TestStep1b_TextualizeOrphanToolResults
    #[test]
    fn textualizes_tool_blocks_without_tools_and_orphans_with_tools() {
        let input = msgs(json!([
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"p": 1}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "out"},
                                          {"type": "tool_result", "tool_use_id": "orphan", "content": "lost"}]}
        ]));
        let no_tools = normalize_messages(&input, false);
        assert_eq!(text(&no_tools[1]), "[Tool: Read (t1)]\n{\"p\":1}");
        assert_eq!(
            text(&no_tools[2]),
            "[Tool Result (t1)]\nout [Tool Result (orphan)]\nlost"
        );
        let with_tools = normalize_messages(&input, true);
        let MessageContent::Blocks(b) = &with_tools[2].content else {
            panic!()
        };
        assert_eq!(b[0].kind, "tool_result");
        assert_eq!(b[1].kind, "text");
        assert_eq!(b[1].text.as_deref(), Some("[Tool Result (orphan)]\nlost"));
    }
}

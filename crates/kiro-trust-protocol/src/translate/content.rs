//! Content extraction from Anthropic blocks. Transcribed from kirocc
//! internal/reqconv/content_text.go, content_scan.go, tool_results.go, images.go.

use crate::anthropic::{ContentBlock, MessageContent, ToolResultContent};
use crate::kiro::{
    HistoryToolUse, Image, ImageSource, TOOL_RESULT_ERROR, TOOL_RESULT_SUCCESS, ToolResult,
    ToolResultContent as KiroResultContent,
};
use serde_json::{Map, Value};

const SKIPPED: &[&str] = &[
    "thinking",
    "redacted_thinking",
    "tool_use",
    "tool_result",
    "image",
    "tool_reference",
    "server_tool_use",
    "tool_search_tool_result",
];

/// Plain text of a message: string as-is; blocks: text joined by a space,
/// handled block kinds skipped, unknown kinds textualized as `[type: name]`.
pub fn extract_text(content: &MessageContent) -> String {
    match content {
        MessageContent::Text(t) => t.clone(),
        MessageContent::Blocks(blocks) => blocks
            .iter()
            .filter_map(|b| {
                if b.kind == "text" {
                    Some(b.text.clone().unwrap_or_default())
                } else if SKIPPED.contains(&b.kind.as_str()) {
                    None
                } else {
                    let ident = b.name.as_deref().or(b.id.as_deref()).unwrap_or("");
                    Some(if ident.is_empty() {
                        format!("[{}]", b.kind)
                    } else {
                        format!("[{}: {}]", b.kind, ident)
                    })
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

pub fn extract_tool_result_text(b: &ContentBlock) -> String {
    match &b.content {
        None => String::new(),
        Some(ToolResultContent::Text(t)) => t.clone(),
        Some(ToolResultContent::Blocks(blocks)) => blocks
            .iter()
            .filter(|cb| cb.kind == "text")
            .map(|cb| cb.text.clone().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn result_json(text: &str, is_error: bool) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "exit_status".into(),
        Value::String(if is_error { "1" } else { "0" }.into()),
    );
    m.insert("stdout".into(), Value::String(text.into()));
    m.insert("stderr".into(), Value::String(String::new()));
    m
}

fn tool_result(b: &ContentBlock, text: String) -> ToolResult {
    let text = if text.is_empty() {
        "(empty result)".to_string()
    } else {
        text
    };
    ToolResult {
        tool_use_id: b.tool_use_id.clone().unwrap_or_default(),
        status: if b.is_error {
            TOOL_RESULT_ERROR
        } else {
            TOOL_RESULT_SUCCESS
        },
        content: vec![KiroResultContent {
            text: None,
            json: Some(result_json(&text, b.is_error)),
        }],
    }
}

/// History form: no image promotion.
pub fn extract_tool_results(content: &MessageContent) -> Vec<ToolResult> {
    let MessageContent::Blocks(blocks) = content else {
        return vec![];
    };
    blocks
        .iter()
        .filter(|b| b.is_tool_result())
        .map(|b| tool_result(b, extract_tool_result_text(b)))
        .collect()
}

pub fn extract_tool_uses(content: &MessageContent) -> Vec<HistoryToolUse> {
    let MessageContent::Blocks(blocks) = content else {
        return vec![];
    };
    blocks
        .iter()
        .filter(|b| b.is_tool_use())
        .map(|b| HistoryToolUse {
            tool_use_id: b.id.clone().unwrap_or_default(),
            name: b.name.clone().unwrap_or_default(),
            input: b.input.clone().unwrap_or(Value::Object(Map::new())),
        })
        .collect()
}

pub fn extract_tool_use_ids(content: &MessageContent) -> Vec<String> {
    extract_tool_uses(content)
        .into_iter()
        .map(|t| t.tool_use_id)
        .collect()
}

fn convert_image(b: &ContentBlock) -> Option<Image> {
    let src = b.source.as_ref()?;
    if src.kind != "base64" {
        return None;
    }
    let format = src.media_type.rsplit('/').next().unwrap_or("").to_string();
    Some(Image {
        format,
        source: ImageSource {
            bytes: src.data.clone(),
        },
    })
}

pub struct Scanned {
    pub tool_results: Vec<ToolResult>,
    pub images: Vec<Image>,
}

/// Current-message form: images nested in tool results are promoted to the
/// message and noted in stdout (kirocc `scanCurrentMessage`).
pub fn scan_current_message(content: &MessageContent) -> Scanned {
    let mut out = Scanned {
        tool_results: vec![],
        images: vec![],
    };
    let MessageContent::Blocks(blocks) = content else {
        return out;
    };
    for b in blocks {
        if b.is_tool_result() {
            let mut text = extract_tool_result_text(b);
            let promoted: Vec<Image> = match &b.content {
                Some(ToolResultContent::Blocks(inner)) => inner
                    .iter()
                    .filter(|cb| cb.kind == "image")
                    .filter_map(convert_image)
                    .collect(),
                _ => vec![],
            };
            if !promoted.is_empty() {
                let notice = format!(
                    "[{} image(s) from this tool result attached to the message]",
                    promoted.len()
                );
                text = if text.is_empty() {
                    notice
                } else {
                    format!("{text}\n{notice}")
                };
                out.images.extend(promoted);
            }
            out.tool_results.push(tool_result(b, text));
        } else if b.kind == "image"
            && let Some(img) = convert_image(b)
        {
            out.images.push(img);
        }
    }
    out
}

/// Reorder results to the preceding assistant's tool_use order; unknown ids
/// keep their relative order at the end.
pub fn reorder_tool_results(results: Vec<ToolResult>, ids: &[String]) -> Vec<ToolResult> {
    if results.len() <= 1 || ids.is_empty() {
        return results;
    }
    let mut ordered = Vec::with_capacity(results.len());
    let mut rest: Vec<Option<ToolResult>> = results.into_iter().map(Some).collect();
    for id in ids {
        if let Some(slot) = rest
            .iter_mut()
            .find(|r| r.as_ref().is_some_and(|r| &r.tool_use_id == id))
        {
            ordered.push(slot.take().unwrap());
        }
    }
    ordered.extend(rest.into_iter().flatten());
    ordered
}

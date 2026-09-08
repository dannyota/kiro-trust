//! Anthropic Messages API types as Claude Code sends and expects them.
//!
//! Content-bearing types deliberately have no `Display` and a `Debug` that
//! prints counts, never text (spec 3.1, 6.4).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Clone, Deserialize)]
pub struct Request {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub system: Option<SystemPrompt>,
    #[serde(default)]
    pub tools: Vec<Tool>,
    #[serde(default)]
    pub max_tokens: u32,
    #[serde(default)]
    pub stop_sequences: Vec<String>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub thinking: Option<ThinkingConfig>,
    #[serde(default)]
    pub output_config: Option<OutputConfig>,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Request {{ model: {:?}, messages: {}, tools: {}, stream: {}, max_tokens: {} }}",
            self.model,
            self.messages.len(),
            self.tools.len(),
            self.stream,
            self.max_tokens
        )
    }
}

impl Request {
    /// `thinking.type` of `enabled` or `adaptive` (spec 5.3 step 8).
    pub fn thinking_enabled(&self) -> bool {
        matches!(
            self.thinking.as_ref().map(|t| t.kind.as_str()),
            Some("enabled" | "adaptive")
        )
    }

    pub fn effort(&self) -> Option<&str> {
        self.output_config
            .as_ref()
            .and_then(|o| o.effort.as_deref())
    }

    /// The system prompt as one string: a string form as-is, blocks joined by
    /// newline (kirocc `ExtractSystemPrompt`).
    pub fn system_text(&self) -> String {
        match &self.system {
            None => String::new(),
            Some(SystemPrompt::Text(t)) => t.clone(),
            Some(SystemPrompt::Blocks(blocks)) => blocks
                .iter()
                .filter(|b| b.kind == "text" && !b.text.is_empty())
                .map(|b| b.text.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    Text(String),
    Blocks(Vec<SystemBlock>),
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SystemBlock {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    /// Any other role string; normalized to `User` by translation.
    #[serde(other)]
    Other,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Message {
    pub role: Role,
    pub content: MessageContent,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// One content block. Modeled as a struct with an open `kind` so unknown
/// block types survive parsing and can be textualized as `[type: name]`.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ToolResultContent>,
    #[serde(default)]
    pub is_error: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ImageSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

impl ContentBlock {
    pub fn is_tool_use(&self) -> bool {
        self.kind == "tool_use" || self.kind == "server_tool_use"
    }
    pub fn is_tool_result(&self) -> bool {
        self.kind == "tool_result" || self.kind == "tool_search_tool_result"
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ImageSource {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub media_type: String,
    #[serde(default)]
    pub data: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CacheControl {
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Tool {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
    #[serde(default)]
    pub defer_loading: bool,
}

impl Tool {
    /// Server-side tool definitions kiro-trust does not emulate (spec 5.3):
    /// tool search and advisor. They are dropped before conversion.
    pub fn is_server_tool(&self) -> bool {
        matches!(self.kind.as_deref(), Some(k) if k.starts_with("tool_search_tool_") || k.starts_with("advisor_"))
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ThinkingConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct OutputConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
}

// ---- Output side -----------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    StopSequence,
}

/// A non-streaming response body.
#[derive(Clone, Serialize, Deserialize)]
pub struct OutMessage {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub role: String,
    pub content: Vec<OutBlock>,
    pub model: String,
    pub stop_reason: Option<StopReason>,
    pub stop_sequence: Option<String>,
    pub usage: Usage,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutBlock {
    Thinking {
        thinking: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    RedactedThinking {
        data: String,
    },
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    MessageStart {
        message: OutMessage,
    },
    ContentBlockStart {
        index: u32,
        content_block: BlockStart,
    },
    ContentBlockDelta {
        index: u32,
        delta: Delta,
    },
    ContentBlockStop {
        index: u32,
    },
    MessageDelta {
        delta: MessageDeltaBody,
        usage: Usage,
    },
    MessageStop,
    Error {
        error: ApiError,
    },
}

impl StreamEvent {
    /// The SSE `event:` name, equal to the JSON `type`.
    pub fn event_name(&self) -> &'static str {
        match self {
            StreamEvent::MessageStart { .. } => "message_start",
            StreamEvent::ContentBlockStart { .. } => "content_block_start",
            StreamEvent::ContentBlockDelta { .. } => "content_block_delta",
            StreamEvent::ContentBlockStop { .. } => "content_block_stop",
            StreamEvent::MessageDelta { .. } => "message_delta",
            StreamEvent::MessageStop => "message_stop",
            StreamEvent::Error { .. } => "error",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BlockStart {
    Text {
        text: String,
    },
    Thinking {
        thinking: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    RedactedThinking {
        data: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: Map<String, Value>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Delta {
    TextDelta { text: String },
    ThinkingDelta { thinking: String },
    SignatureDelta { signature: String },
    InputJsonDelta { partial_json: String },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MessageDeltaBody {
    pub stop_reason: StopReason,
    pub stop_sequence: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    #[serde(rename = "type")]
    pub kind: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_claude_code_shaped_request() {
        let raw = r#"{
          "model": "claude-sonnet-4-6",
          "max_tokens": 1024,
          "stream": true,
          "system": [{"type": "text", "text": "You are terse.", "cache_control": {"type": "ephemeral"}}],
          "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [{"type": "text", "text": "hello"},
              {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"path": "a.rs"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1",
              "content": [{"type": "text", "text": "fn main() {}"}], "is_error": false},
              {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]}
          ],
          "tools": [{"name": "Read", "description": "Read a file",
                     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
                     "cache_control": {"type": "ephemeral"}},
                    {"type": "tool_search_tool_regex_20251119", "name": "tool_search"}],
          "thinking": {"type": "enabled", "budget_tokens": 2048},
          "output_config": {"effort": "high"},
          "stop_sequences": ["END"],
          "metadata": {"user_id": "ignored"}
        }"#;
        let req: Request = serde_json::from_str(raw).unwrap();
        assert_eq!(req.model, "claude-sonnet-4-6");
        assert_eq!(req.max_tokens, 1024);
        assert!(req.stream);
        assert_eq!(req.messages.len(), 3);
        assert_eq!(req.messages[0].role, Role::User);
        assert!(matches!(req.messages[0].content, MessageContent::Text(ref t) if t == "hi"));
        let MessageContent::Blocks(blocks) = &req.messages[1].content else {
            panic!()
        };
        assert_eq!(blocks[1].kind, "tool_use");
        assert_eq!(blocks[1].name.as_deref(), Some("Read"));
        let MessageContent::Blocks(blocks) = &req.messages[2].content else {
            panic!()
        };
        assert_eq!(blocks[0].tool_use_id.as_deref(), Some("toolu_1"));
        assert_eq!(blocks[1].source.as_ref().unwrap().media_type, "image/png");
        assert_eq!(req.tools.len(), 2);
        assert!(req.tools[1].is_server_tool());
        assert!(!req.tools[0].is_server_tool());
        assert!(req.thinking_enabled());
        assert_eq!(req.effort(), Some("high"));
        assert_eq!(req.system_text(), "You are terse.");
    }

    #[test]
    fn unknown_block_types_keep_their_type_string() {
        let raw = r#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"mystery","name":"x"}]}]}"#;
        let req: Request = serde_json::from_str(raw).unwrap();
        let MessageContent::Blocks(blocks) = &req.messages[0].content else {
            panic!()
        };
        assert_eq!(blocks[0].kind, "mystery");
    }

    #[test]
    fn request_debug_prints_counts_only() {
        let raw = r#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"SECRET PROMPT"}]}"#;
        let req: Request = serde_json::from_str(raw).unwrap();
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("SECRET PROMPT"));
        assert!(dbg.contains("messages: 1"));
    }

    #[test]
    fn stream_events_serialize_in_anthropic_shape() {
        let ev = StreamEvent::ContentBlockDelta {
            index: 2,
            delta: Delta::TextDelta { text: "hi".into() },
        };
        assert_eq!(
            serde_json::to_string(&ev).unwrap(),
            r#"{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"hi"}}"#
        );
        let start = StreamEvent::ContentBlockStart {
            index: 0,
            content_block: BlockStart::ToolUse {
                id: "toolu_1".into(),
                name: "Read".into(),
                input: serde_json::Map::new(),
            },
        };
        assert_eq!(
            serde_json::to_string(&start).unwrap(),
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}}"#
        );
        assert_eq!(
            serde_json::to_string(&StreamEvent::MessageStop).unwrap(),
            r#"{"type":"message_stop"}"#
        );
        assert_eq!(StreamEvent::MessageStop.event_name(), "message_stop");
    }
}

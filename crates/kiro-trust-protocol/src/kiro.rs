//! Kiro runtime request payload (spec 7.6) and decoded stream events (spec 7.5).
//! Field declaration order is the wire order; serde_json preserves it.

use serde::Serialize;
use serde_json::{Map, Value};

pub const ORIGIN_KIRO_CLI: &str = "KIRO_CLI";
pub const CHAT_TRIGGER_MANUAL: &str = "MANUAL";
pub const AGENT_TASK_VIBE: &str = "vibe";
pub const TOOL_RESULT_SUCCESS: &str = "success";
pub const TOOL_RESULT_ERROR: &str = "error";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Payload {
    pub conversation_state: ConversationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_model_request_fields: Option<AdditionalModelRequestFields>,
}

/// `output_config` is snake_case on the wire, unlike everything else.
#[derive(Clone, Serialize)]
pub struct AdditionalModelRequestFields {
    pub output_config: OutputConfig,
}

#[derive(Clone, Serialize)]
pub struct OutputConfig {
    pub effort: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    pub chat_trigger_type: &'static str,
    pub agent_task_type: &'static str,
    pub current_message: CurrentMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentMessage {
    pub user_input_message: UserInputMessage,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInputMessage {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_input_message_context: Option<UserInputMessageContext>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<Image>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_point: Option<CachePoint>,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInputMessageContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_state: Option<EnvState>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_results: Vec<ToolResult>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_working_directory: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ToolEntry {
    ToolSpecification(ToolSpecification),
    CachePoint(CachePoint),
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSpecification {
    pub name: String,
    pub description: String,
    pub input_schema: InputSchema,
}

#[derive(Clone, Serialize)]
pub struct InputSchema {
    pub json: Map<String, Value>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    pub tool_use_id: String,
    pub status: &'static str,
    pub content: Vec<ToolResultContent>,
}

/// Exactly one of `text` or `json` is set. Callers build tool results with
/// `json` (the exit_status/stdout/stderr shape kiro-cli sends); `text` exists
/// for parity with the Kiro schema.
#[derive(Clone, Serialize)]
pub struct ToolResultContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<Map<String, Value>>,
}

#[derive(Clone, Serialize)]
pub struct Image {
    pub format: String,
    pub source: ImageSource,
}

#[derive(Clone, Serialize)]
pub struct ImageSource {
    pub bytes: String,
}

#[derive(Clone, Serialize)]
pub struct CachePoint {
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HistoryEntry {
    UserInputMessage(HistoryUserInputMessage),
    AssistantResponseMessage(AssistantResponseMessage),
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryUserInputMessage {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_input_message_context: Option<UserInputMessageContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_point: Option<CachePoint>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantResponseMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    pub content: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_uses: Vec<HistoryToolUse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_point: Option<CachePoint>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryToolUse {
    pub tool_use_id: String,
    pub name: String,
    pub input: Value,
}

/// A decoded upstream event (spec 7.5). Tool use events arrive complete:
/// fragments are joined by `eventstream::EventParser`.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    AssistantResponse {
        content: String,
    },
    ReasoningContent {
        text: String,
        signature: Option<String>,
        redacted_content: Option<String>,
    },
    ToolUse {
        tool_use_id: String,
        name: String,
        input: String,
    },
    Metadata {
        uncached_input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
        cache_read_input_tokens: u64,
        cache_write_input_tokens: u64,
    },
    Metering {
        credits: f64,
        input_tokens: u64,
        output_tokens: u64,
    },
    InvalidState {
        reason: String,
        message: String,
    },
    Exception {
        exception_type: String,
        message: String,
    },
    Ignored {
        event_type: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // Transcribed from kirocc kiroproto/types_test.go TestPayload_MarshalJSON_Minimal
    // and TestToolEntry_MarshalJSON_*: wire field order and omitted empties.
    #[test]
    fn minimal_payload_wire_shape() {
        let p = Payload {
            conversation_state: ConversationState {
                conversation_id: Some("c1".into()),
                chat_trigger_type: CHAT_TRIGGER_MANUAL,
                agent_task_type: AGENT_TASK_VIBE,
                current_message: CurrentMessage {
                    user_input_message: UserInputMessage {
                        content: "hi".into(),
                        model_id: Some("claude-sonnet-4.6".into()),
                        origin: Some(ORIGIN_KIRO_CLI),
                        user_input_message_context: None,
                        images: vec![],
                        cache_point: None,
                    },
                },
                history: vec![],
            },
            profile_arn: Some("arn:test".into()),
            additional_model_request_fields: Some(AdditionalModelRequestFields {
                output_config: OutputConfig {
                    effort: "medium".into(),
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"conversationState":{"conversationId":"c1","chatTriggerType":"MANUAL","agentTaskType":"vibe","currentMessage":{"userInputMessage":{"content":"hi","modelId":"claude-sonnet-4.6","origin":"KIRO_CLI"}}},"profileArn":"arn:test","additionalModelRequestFields":{"output_config":{"effort":"medium"}}}"#
        );
    }

    #[test]
    fn tool_entries_and_history_are_externally_tagged() {
        let spec = ToolEntry::ToolSpecification(ToolSpecification {
            name: "Read".into(),
            description: "Read a file".into(),
            input_schema: InputSchema {
                json: serde_json::Map::new(),
            },
        });
        assert_eq!(
            serde_json::to_string(&spec).unwrap(),
            r#"{"toolSpecification":{"name":"Read","description":"Read a file","inputSchema":{"json":{}}}}"#
        );
        let cp = ToolEntry::CachePoint(CachePoint {
            kind: "default".into(),
        });
        assert_eq!(
            serde_json::to_string(&cp).unwrap(),
            r#"{"cachePoint":{"type":"default"}}"#
        );
        let h = HistoryEntry::AssistantResponseMessage(AssistantResponseMessage {
            message_id: Some("m1".into()),
            content: "ok".into(),
            tool_uses: vec![HistoryToolUse {
                tool_use_id: "t1".into(),
                name: "Read".into(),
                input: serde_json::json!({"path": "a"}),
            }],
            cache_point: None,
        });
        assert_eq!(
            serde_json::to_string(&h).unwrap(),
            r#"{"assistantResponseMessage":{"messageId":"m1","content":"ok","toolUses":[{"toolUseId":"t1","name":"Read","input":{"path":"a"}}]}}"#
        );
    }
}

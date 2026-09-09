//! Anthropic request → Kiro payload (spec 5.3). Transcribed from kirocc
//! internal/reqconv/build_payload.go.

use super::content::{
    extract_text, extract_tool_use_ids, reorder_tool_results, scan_current_message,
};
use super::env_state::parse_env_state;
use super::history::{build_history, place_system_prompt};
use super::normalize::{SYNTHETIC_CONTINUE, normalize_messages};
use super::tool_names::ToolNameMap;
use super::tools::{apply_tool_cache_points, callable_tools, convert_tools};
use crate::anthropic::{Message, MessageContent, Request, Role};
use crate::kiro::{
    AGENT_TASK_VIBE, AdditionalModelRequestFields, CHAT_TRIGGER_MANUAL, ConversationState,
    CurrentMessage, ORIGIN_KIRO_CLI, OutputConfig, Payload, UserInputMessage,
    UserInputMessageContext,
};

#[derive(Clone, Debug)]
pub struct BuildOptions {
    pub profile_arn: Option<String>,
    pub model_id: String,
    pub conversation_id: Option<String>,
    pub effort: Option<String>,
}

pub struct Built {
    pub payload: Payload,
    pub tool_names: ToolNameMap,
}

pub fn build_payload(req: &Request, opts: &BuildOptions) -> Built {
    let mut names = ToolNameMap::default();
    let system = req.system_text();
    let callable = callable_tools(&req.tools);
    let tool_entries = if callable.is_empty() {
        vec![]
    } else {
        apply_tool_cache_points(&callable, convert_tools(&callable, &mut names))
    };
    let env_state = parse_env_state(&system);
    let msgs = normalize_messages(&req.messages, !tool_entries.is_empty());
    let (history_msgs, last) = split_messages(&msgs);
    let scanned = scan_current_message(&last.content);
    let history = place_system_prompt(&system, build_history(&history_msgs, &mut names));
    let preceding_ids = history_msgs
        .last()
        .filter(|m| m.role == Role::Assistant)
        .map(|m| extract_tool_use_ids(&m.content))
        .unwrap_or_default();

    let mut current = UserInputMessage {
        content: extract_text(&last.content),
        model_id: Some(opts.model_id.clone()),
        origin: Some(ORIGIN_KIRO_CLI),
        user_input_message_context: None,
        images: scanned.images,
        cache_point: None,
    };
    let tool_results = reorder_tool_results(scanned.tool_results, &preceding_ids);
    if env_state.is_some() || !tool_entries.is_empty() || !tool_results.is_empty() {
        current.user_input_message_context = Some(UserInputMessageContext {
            env_state,
            tools: tool_entries,
            tool_results: tool_results.clone(),
        });
    }
    if current.content.is_empty() && tool_results.is_empty() {
        current.content = SYNTHETIC_CONTINUE.to_string();
    }

    let payload = Payload {
        conversation_state: ConversationState {
            conversation_id: opts.conversation_id.clone(),
            chat_trigger_type: CHAT_TRIGGER_MANUAL,
            agent_task_type: AGENT_TASK_VIBE,
            current_message: CurrentMessage {
                user_input_message: current,
            },
            history,
        },
        profile_arn: opts.profile_arn.clone(),
        additional_model_request_fields: opts.effort.as_ref().map(|e| {
            AdditionalModelRequestFields {
                output_config: OutputConfig { effort: e.clone() },
            }
        }),
    };
    Built {
        payload,
        tool_names: names,
    }
}

fn split_messages(msgs: &[Message]) -> (Vec<Message>, Message) {
    match msgs.last() {
        None => (
            vec![],
            Message {
                role: Role::User,
                content: MessageContent::Text(String::new()),
            },
        ),
        Some(last) if last.role == Role::Assistant => (
            msgs.to_vec(),
            Message {
                role: Role::User,
                content: MessageContent::Text(SYNTHETIC_CONTINUE.into()),
            },
        ),
        Some(last) => (msgs[..msgs.len() - 1].to_vec(), last.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::Request;
    use crate::translate::history::SYNTHETIC_ACK;
    use serde_json::{Value, json};

    fn req(v: Value) -> Request {
        serde_json::from_value(v).unwrap()
    }
    fn opts() -> BuildOptions {
        BuildOptions {
            profile_arn: Some("arn:test".into()),
            model_id: "claude-sonnet-4.6".into(),
            conversation_id: Some("conv-1".into()),
            effort: None,
        }
    }
    fn payload_json(req: &Request, o: &BuildOptions) -> Value {
        serde_json::to_value(&build_payload(req, o).payload).unwrap()
    }

    // kirocc TestBuildPayload_SimpleMessage, _NoContextWhenNoToolsOrResults, _EmptyProfileARN
    #[test]
    fn simple_message() {
        let p = payload_json(
            &req(
                json!({"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": "hello"}]}),
            ),
            &opts(),
        );
        assert_eq!(
            p,
            json!({
                "conversationState": {
                    "conversationId": "conv-1", "chatTriggerType": "MANUAL", "agentTaskType": "vibe",
                    "currentMessage": {"userInputMessage": {"content": "hello", "modelId": "claude-sonnet-4.6", "origin": "KIRO_CLI"}}
                },
                "profileArn": "arn:test"
            })
        );
        let mut o = opts();
        o.profile_arn = None;
        let p = payload_json(
            &req(
                json!({"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": "hello"}]}),
            ),
            &o,
        );
        assert!(p.get("profileArn").is_none());
    }

    // kirocc TestBuildPayload_SystemPromptInHistory, TestPlaceSystemPrompt_*, _AssistantMessageID
    #[test]
    fn system_prompt_becomes_history_pair_with_deterministic_ids() {
        let r = req(json!({"model": "m", "max_tokens": 5, "system": "Be terse.",
            "messages": [{"role": "user", "content": "one"}, {"role": "assistant", "content": "two"}, {"role": "user", "content": "three"}]}));
        let p = payload_json(&r, &opts());
        let history = p["conversationState"]["history"].as_array().unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0]["userInputMessage"]["content"], "Be terse.");
        assert_eq!(history[0]["userInputMessage"]["origin"], "KIRO_CLI");
        assert_eq!(
            history[1]["assistantResponseMessage"]["content"],
            SYNTHETIC_ACK
        );
        assert!(
            history[1]["assistantResponseMessage"]["messageId"].is_string(),
            "synthetic ack carries a deterministic id"
        );
        assert_eq!(history[2]["userInputMessage"]["content"], "one");
        assert_eq!(history[3]["assistantResponseMessage"]["content"], "two");
        let id_a = history[3]["assistantResponseMessage"]["messageId"]
            .as_str()
            .unwrap()
            .to_string();
        let p2 = payload_json(&r, &opts());
        assert_eq!(
            p2["conversationState"]["history"][3]["assistantResponseMessage"]["messageId"], id_a,
            "stable across requests"
        );
        assert_eq!(
            p["conversationState"]["currentMessage"]["userInputMessage"]["content"],
            "three"
        );
    }

    // kirocc TestBuildPayload_LastAssistant
    #[test]
    fn trailing_assistant_message_gets_continue() {
        let r = req(json!({"model": "m", "max_tokens": 5,
            "messages": [{"role": "user", "content": "one"}, {"role": "assistant", "content": "two"}]}));
        let p = payload_json(&r, &opts());
        assert_eq!(
            p["conversationState"]["currentMessage"]["userInputMessage"]["content"],
            "Continue"
        );
        assert_eq!(
            p["conversationState"]["history"].as_array().unwrap().len(),
            2
        );
    }

    // kirocc TestBuildPayload_ToolUseFlow, _ToolResultsInHistory, TestReorderToolResults
    #[test]
    fn tool_use_flow_orders_results_and_uses_exit_status_shape() {
        let r = req(json!({"model": "m", "max_tokens": 5,
        "tools": [{"name": "Read", "description": "r", "input_schema": {"type": "object"}},
                  {"name": "Bash", "description": "b", "input_schema": {"type": "object"}}],
        "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "calling"},
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"path": "a"}},
                {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"cmd": "ls"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t2", "content": "b\nc"},
                {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "x"}], "is_error": true}]}
        ]}));
        let p = payload_json(&r, &opts());
        let current = &p["conversationState"]["currentMessage"]["userInputMessage"];
        assert_eq!(
            current["content"], "",
            "tool-result-only turn keeps empty content"
        );
        let results = current["userInputMessageContext"]["toolResults"]
            .as_array()
            .unwrap();
        assert_eq!(
            results[0]["toolUseId"], "t1",
            "reordered to the assistant's tool_use order"
        );
        assert_eq!(results[0]["status"], "error");
        assert_eq!(
            results[0]["content"][0]["json"],
            json!({"exit_status": "1", "stdout": "x", "stderr": ""})
        );
        assert_eq!(results[1]["toolUseId"], "t2");
        assert_eq!(results[1]["content"][0]["json"]["stdout"], "b\nc");
        let tools = current["userInputMessageContext"]["tools"]
            .as_array()
            .unwrap();
        assert_eq!(tools.len(), 2);
        let history = p["conversationState"]["history"].as_array().unwrap();
        let arm = &history[1]["assistantResponseMessage"];
        assert_eq!(arm["content"], "calling");
        assert_eq!(arm["toolUses"].as_array().unwrap().len(), 2);
        assert_eq!(arm["toolUses"][0]["input"], json!({"path": "a"}));
    }

    // kirocc TestBuildPayload_EnvStateOnCurrentMessageOnly, _EnvStateOmittedWhenNil
    #[test]
    fn env_state_from_system_prompt_only_on_current_message() {
        let system = "Intro\n<env>\nWorking directory: /home/user/proj\nPlatform: darwin\nOS Version: 1\n</env>\nOutro";
        let r = req(json!({"model": "m", "max_tokens": 5, "system": system,
            "messages": [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "c"}]}));
        let p = payload_json(&r, &opts());
        assert_eq!(
            p["conversationState"]["currentMessage"]["userInputMessage"]["userInputMessageContext"]
                ["envState"],
            json!({"operatingSystem": "macos", "currentWorkingDirectory": "/home/user/proj"})
        );
        for h in p["conversationState"]["history"].as_array().unwrap() {
            if let Some(u) = h.get("userInputMessage") {
                assert!(u.get("userInputMessageContext").is_none());
            }
        }
        let r = req(
            json!({"model": "m", "max_tokens": 5, "system": "no env block", "messages": [{"role": "user", "content": "a"}]}),
        );
        let p = payload_json(&r, &opts());
        assert!(
            p["conversationState"]["currentMessage"]["userInputMessage"]
                .get("userInputMessageContext")
                .is_none()
        );
    }

    #[test]
    fn images_and_thinking_blocks() {
        let r = req(json!({"model": "m", "max_tokens": 5, "messages": [
            {"role": "user", "content": "look"},
            {"role": "assistant", "content": [{"type": "thinking", "thinking": "hmm", "signature": "s"}, {"type": "text", "text": "ok"}]},
            {"role": "user", "content": [{"type": "text", "text": "see"}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]}
        ]}));
        let p = payload_json(&r, &opts());
        assert_eq!(
            p["conversationState"]["history"][1]["assistantResponseMessage"]["content"], "ok",
            "thinking dropped from history"
        );
        let current = &p["conversationState"]["currentMessage"]["userInputMessage"];
        assert_eq!(current["content"], "see");
        assert_eq!(
            current["images"],
            json!([{"format": "png", "source": {"bytes": "AAAA"}}])
        );
    }

    #[test]
    fn effort_and_tools_cache_point_and_server_tools() {
        let mut o = opts();
        o.effort = Some("high".into());
        let r = req(json!({"model": "m", "max_tokens": 5,
            "tools": [{"name": "Read", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral"}},
                      {"type": "tool_search_tool_regex_20251119", "name": "tool_search"}],
            "messages": [{"role": "user", "content": "x"}]}));
        let built = build_payload(&r, &o);
        let p = serde_json::to_value(&built.payload).unwrap();
        assert_eq!(
            p["additionalModelRequestFields"],
            json!({"output_config": {"effort": "high"}})
        );
        let tools =
            p["conversationState"]["currentMessage"]["userInputMessage"]["userInputMessageContext"]
                ["tools"]
                .as_array()
                .unwrap();
        assert_eq!(tools.len(), 2);
        assert!(tools[1].get("cachePoint").is_some());
        assert!(built.payload.conversation_state.history.is_empty());
    }
}

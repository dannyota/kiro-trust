//! Anthropic tool definitions → Kiro tool entries. Transcribed from kirocc
//! internal/reqconv/tool_convert.go and cache_points.go.

use super::schema::{ensure_object_root, sanitize_schema};
use super::tool_names::ToolNameMap;
use crate::anthropic::Tool;
use crate::kiro::{CachePoint, InputSchema, ToolEntry, ToolSpecification};

/// Tools forwarded to Kiro: server-side definitions (tool search, advisor)
/// are dropped; `defer_loading` is ignored so deferred tools stay active
/// (spec 5.3 step 2).
pub fn callable_tools(tools: &[Tool]) -> Vec<Tool> {
    tools
        .iter()
        .filter(|t| !t.is_server_tool())
        .cloned()
        .collect()
}

pub fn convert_tools(tools: &[Tool], names: &mut ToolNameMap) -> Vec<ToolEntry> {
    tools
        .iter()
        .map(|t| {
            let name = names.shorten(&t.name);
            let description = if t.description.is_empty() {
                format!("Tool: {}", t.name)
            } else {
                t.description.clone()
            };
            let schema = t.input_schema.clone().unwrap_or_default();
            ToolEntry::ToolSpecification(ToolSpecification {
                name,
                description,
                input_schema: InputSchema {
                    json: ensure_object_root(sanitize_schema(&schema)),
                },
            })
        })
        .collect()
}

/// Insert a `cachePoint` after every tool that carries `cache_control`.
pub fn apply_tool_cache_points(tools: &[Tool], entries: Vec<ToolEntry>) -> Vec<ToolEntry> {
    let mut out = Vec::with_capacity(entries.len() + 1);
    let mut entries = entries.into_iter();
    for t in tools {
        if let Some(e) = entries.next() {
            out.push(e);
        }
        if t.cache_control.is_some() {
            out.push(ToolEntry::CachePoint(CachePoint {
                kind: "default".into(),
            }));
        }
    }
    out.extend(entries);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::{CacheControl, Tool};
    use crate::kiro::ToolEntry;
    use serde_json::json;

    fn tool(name: &str, desc: &str, cache: bool) -> Tool {
        Tool {
            kind: None,
            name: name.into(),
            description: desc.into(),
            input_schema: Some(
                json!({"type": "object", "properties": {}})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            cache_control: cache.then(|| CacheControl {
                kind: "ephemeral".into(),
            }),
            defer_loading: false,
        }
    }

    // kirocc TestConvertTools_Basic, _EmptyDescription, _LongNameShortened, cache_points_test
    #[test]
    fn converts_tools_and_inserts_cache_points() {
        let mut server = tool("tool_search", "", false);
        server.kind = Some("tool_search_tool_regex_20251119".into());
        let mut deferred = tool("Deferred", "d", false);
        deferred.defer_loading = true;
        let tools = vec![
            tool("Read", "", true),
            server,
            deferred,
            tool("Bash", "Run", false),
        ];
        let callable = callable_tools(&tools);
        assert_eq!(
            callable.len(),
            3,
            "server tools dropped, deferred tools kept active"
        );
        let mut names = ToolNameMap::default();
        let entries = apply_tool_cache_points(&callable, convert_tools(&callable, &mut names));
        assert_eq!(entries.len(), 4);
        let ToolEntry::ToolSpecification(spec) = &entries[0] else {
            panic!()
        };
        assert_eq!(spec.description, "Tool: Read");
        assert!(matches!(entries[1], ToolEntry::CachePoint(ref c) if c.kind == "default"));
        let ToolEntry::ToolSpecification(spec) = &entries[2] else {
            panic!()
        };
        assert_eq!(spec.name, "Deferred");
        let ToolEntry::ToolSpecification(spec) = &entries[3] else {
            panic!()
        };
        assert_eq!(spec.input_schema.json["type"], "object");
    }

    #[test]
    fn missing_schema_becomes_empty_object() {
        let mut t = tool("X", "x", false);
        t.input_schema = None;
        let mut names = ToolNameMap::default();
        let entries = convert_tools(&[t], &mut names);
        let ToolEntry::ToolSpecification(spec) = &entries[0] else {
            panic!()
        };
        assert_eq!(
            serde_json::Value::Object(spec.input_schema.json.clone()),
            json!({"type": "object", "properties": {}})
        );
    }
}

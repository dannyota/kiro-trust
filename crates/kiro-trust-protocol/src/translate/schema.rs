//! JSON Schema sanitization for Kiro tool specifications. Transcribed from
//! kirocc v0.11.1 internal/reqconv/schema_sanitize.go (see NOTICE).

use serde_json::{Map, Value};

const UNSUPPORTED: &[&str] = &[
    "additionalProperties",
    "$schema",
    "propertyNames",
    "default",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "$defs",
    "$ref",
    "patternProperties",
    "if",
    "then",
    "else",
    "dependentRequired",
    "dependentSchemas",
    "prefixItems",
    "unevaluatedProperties",
    "unevaluatedItems",
    "contentMediaType",
    "contentEncoding",
    "format",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "uniqueItems",
    "multipleOf",
    "not",
];

pub fn sanitize_schema(schema: &Map<String, Value>) -> Map<String, Value> {
    let mut result = Map::new();
    for (key, value) in schema {
        if UNSUPPORTED.contains(&key.as_str()) {
            continue;
        }
        match key.as_str() {
            "const" => {
                result.insert("enum".into(), Value::Array(vec![value.clone()]));
            }
            "required" => {
                if let Value::Array(a) = value
                    && a.is_empty()
                {
                    continue;
                }
                result.insert(key.clone(), value.clone());
            }
            // `properties` keys are parameter names, not schema keywords: a
            // property literally named `format`, `default`, `const`, etc.
            // must survive untouched. Only each property's own value is a
            // schema and gets sanitized.
            "properties" => {
                if let Value::Object(props) = value {
                    let sanitized: Map<String, Value> = props
                        .iter()
                        .map(|(k, v)| (k.clone(), sanitize_value(v)))
                        .collect();
                    result.insert(key.clone(), Value::Object(sanitized));
                } else {
                    result.insert(key.clone(), value.clone());
                }
            }
            "anyOf" | "oneOf" | "allOf" => {}
            _ => {
                result.insert(key.clone(), sanitize_value(value));
            }
        }
    }
    // Combinators apply last so they deterministically override.
    for (key, value) in schema {
        match key.as_str() {
            "anyOf" | "oneOf" => {
                let Value::Array(branches) = value else {
                    continue;
                };
                if branches.is_empty() {
                    continue;
                }
                // Sanitize each object branch exactly once (`None` for a
                // non-object branch) so nested anyOf/oneOf costs O(depth)
                // instead of doubling per level between the enum-flatten
                // attempt and the fallback below.
                let sanitized: Vec<Option<Map<String, Value>>> = branches
                    .iter()
                    .map(|b| match b {
                        Value::Object(m) => Some(sanitize_schema(m)),
                        _ => None,
                    })
                    .collect();
                if let Some(merged) = flatten_enum_branches(&sanitized) {
                    result.extend(merged);
                } else {
                    let non_null = drop_null_branches(&sanitized);
                    if non_null.len() == 1 {
                        if let Some(m) = non_null[0] {
                            result.extend(m.clone());
                        }
                    } else if let Some(first) = sanitized.first().and_then(|s| s.as_ref()) {
                        result.extend(first.clone());
                    }
                }
            }
            "allOf" => {
                if let Value::Array(items) = value {
                    for item in items {
                        if let Value::Object(m) = item {
                            result.extend(sanitize_schema(m));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    result
}

fn sanitize_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(sanitize_schema(m)),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|i| match i {
                    Value::Object(m) => Value::Object(sanitize_schema(m)),
                    other => other.clone(),
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Branches already sanitized once by the caller; `None` marks a branch that
/// was not an object. A branch is dropped only when it sanitized to
/// `{"type": "null"}`.
fn drop_null_branches(branches: &[Option<Map<String, Value>>]) -> Vec<&Option<Map<String, Value>>> {
    branches
        .iter()
        .filter(|s| !matches!(s, Some(m) if m.get("type") == Some(&Value::String("null".into()))))
        .collect()
}

/// Branches already sanitized once by the caller (see `drop_null_branches`).
fn flatten_enum_branches(branches: &[Option<Map<String, Value>>]) -> Option<Map<String, Value>> {
    let mut all = Vec::new();
    let mut typ: Option<String> = None;
    let mut consistent = true;
    for b in branches {
        let s = b.as_ref()?;
        let Some(Value::Array(e)) = s.get("enum") else {
            return None;
        };
        all.extend(e.iter().cloned());
        match s.get("type").and_then(Value::as_str) {
            Some(t) => match &typ {
                None => typ = Some(t.to_string()),
                Some(prev) if prev != t => consistent = false,
                _ => {}
            },
            None => consistent = false,
        }
    }
    let mut merged = Map::new();
    merged.insert("enum".into(), Value::Array(all));
    if let Some(t) = typ
        && consistent
    {
        merged.insert("type".into(), Value::String(t));
    }
    Some(merged)
}

/// Kiro rejects a tool whose root type is not `object`.
pub fn ensure_object_root(mut schema: Map<String, Value>) -> Map<String, Value> {
    if schema.is_empty() {
        let mut m = Map::new();
        m.insert("type".into(), Value::String("object".into()));
        m.insert("properties".into(), Value::Object(Map::new()));
        return m;
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => schema,
        None => {
            schema.insert("type".into(), Value::String("object".into()));
            schema
        }
        Some(_) => {
            let mut props = Map::new();
            props.insert("input".into(), Value::Object(schema));
            let mut m = Map::new();
            m.insert("type".into(), Value::String("object".into()));
            m.insert("properties".into(), Value::Object(props));
            m
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: serde_json::Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    // kirocc TestSanitizeJSONSchema_RemovesAdditionalProperties, _RemovesValidationKeywords,
    // _RemovesEmptyRequired, _KeepsNonEmptyRequired, _ConstToEnum
    #[test]
    fn drops_unsupported_keywords_recursively() {
        let s = obj(json!({
            "type": "object", "$schema": "x", "additionalProperties": false,
            "required": [],
            "properties": {
                "a": {"type": "string", "minLength": 1, "pattern": "^a", "format": "uri"},
                "b": {"const": "fixed"},
                "c": {"type": "array", "items": {"type": "object", "additionalProperties": false, "required": ["x"], "properties": {"x": {"type": "integer", "minimum": 0}}}}
            }
        }));
        let got = sanitize_schema(&s);
        assert_eq!(
            Value::Object(got),
            json!({
                "type": "object",
                "properties": {
                    "a": {"type": "string"},
                    "b": {"enum": ["fixed"]},
                    "c": {"type": "array", "items": {"type": "object", "required": ["x"], "properties": {"x": {"type": "integer"}}}}
                }
            })
        );
    }

    // kirocc TestSanitizeJSONSchema_FlattensAnyOfEnums, _AnyOfNullable_NoWarning,
    // _AnyOfNonEnum_UsesFirstBranch, _AllOfMerged, _AnyOfOverridesType_Deterministic
    #[test]
    fn flattens_combinators() {
        let enums = obj(
            json!({"anyOf": [{"type": "string", "enum": ["a"]}, {"type": "string", "enum": ["b"]}]}),
        );
        assert_eq!(
            Value::Object(sanitize_schema(&enums)),
            json!({"enum": ["a", "b"], "type": "string"})
        );

        let nullable = obj(json!({"anyOf": [{"type": "string"}, {"type": "null"}]}));
        assert_eq!(
            Value::Object(sanitize_schema(&nullable)),
            json!({"type": "string"})
        );

        let first = obj(json!({"oneOf": [{"type": "number", "minimum": 1}, {"type": "string"}]}));
        assert_eq!(
            Value::Object(sanitize_schema(&first)),
            json!({"type": "number"})
        );

        let all = obj(
            json!({"allOf": [{"type": "object", "properties": {"a": {"type": "string"}}}, {"required": ["a"]}]}),
        );
        assert_eq!(
            Value::Object(sanitize_schema(&all)),
            json!({"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]})
        );

        let overrides =
            obj(json!({"type": "integer", "anyOf": [{"type": "string", "enum": ["x"]}]}));
        assert_eq!(
            Value::Object(sanitize_schema(&overrides)),
            json!({"type": "string", "enum": ["x"]})
        );
    }

    // Regression: flatten_enum_branches previously re-sanitized each branch
    // that the fallback path also sanitized, doubling cost per nesting
    // level. A non-enum leaf forces the fallback on every level, so depth 40
    // used to be computationally infeasible; it must now complete in linear
    // time.
    #[test]
    fn nested_any_of_sanitizes_in_linear_time() {
        let mut schema = json!({"type": "string"});
        for _ in 0..40 {
            schema = json!({"anyOf": [schema]});
        }
        let s = obj(schema);
        let start = std::time::Instant::now();
        let got = sanitize_schema(&s);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 500,
            "sanitize_schema took {elapsed:?} for depth 40, expected linear time"
        );
        assert_eq!(Value::Object(got), json!({"type": "string"}));
    }

    // Regression: `properties` keys are parameter names, not schema
    // keywords, and must never be filtered or rewritten by the keyword list
    // or the const/required special cases. Only each property's value is a
    // schema.
    #[test]
    fn properties_named_after_keywords_survive() {
        let s = obj(json!({
            "type": "object",
            "properties": {
                "format": {"type": "string", "minLength": 1},
                "default": {"type": "string"},
                "const": {"type": "string"},
                "pattern": {"type": "string"},
                "required": {"type": "string"},
                "ok": {"type": "string"}
            }
        }));
        assert_eq!(
            Value::Object(sanitize_schema(&s)),
            json!({
                "type": "object",
                "properties": {
                    "format": {"type": "string"},
                    "default": {"type": "string"},
                    "const": {"type": "string"},
                    "pattern": {"type": "string"},
                    "required": {"type": "string"},
                    "ok": {"type": "string"}
                }
            })
        );
    }

    // kirocc TestEnsureObjectRoot_*
    #[test]
    fn ensures_object_root() {
        assert_eq!(
            Value::Object(ensure_object_root(Map::new())),
            json!({"type": "object", "properties": {}})
        );
        assert_eq!(
            Value::Object(ensure_object_root(obj(
                json!({"type": "object", "properties": {}})
            ))),
            json!({"type": "object", "properties": {}})
        );
        assert_eq!(
            Value::Object(ensure_object_root(obj(
                json!({"properties": {"q": {"type": "string"}}})
            ))),
            json!({"properties": {"q": {"type": "string"}}, "type": "object"})
        );
        assert_eq!(
            Value::Object(ensure_object_root(obj(json!({"type": "string"})))),
            json!({"type": "object", "properties": {"input": {"type": "string"}}})
        );
        assert_eq!(
            Value::Object(ensure_object_root(obj(
                json!({"type": "array", "items": {}})
            ))),
            json!({"type": "object", "properties": {"input": {"type": "array", "items": {}}}})
        );
    }
}

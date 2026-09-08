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
                if let Some(merged) = flatten_enum_branches(branches) {
                    result.extend(merged);
                } else {
                    let non_null = drop_null_branches(branches);
                    if non_null.len() == 1 {
                        if let Value::Object(m) = non_null[0] {
                            result.extend(sanitize_schema(m));
                        }
                    } else if let Some(Value::Object(first)) = branches.first() {
                        result.extend(sanitize_schema(first));
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

fn drop_null_branches(branches: &[Value]) -> Vec<&Value> {
    branches
        .iter()
        .filter(|b| !matches!(b, Value::Object(m) if m.get("type") == Some(&Value::String("null".into()))))
        .collect()
}

fn flatten_enum_branches(branches: &[Value]) -> Option<Map<String, Value>> {
    let mut all = Vec::new();
    let mut typ: Option<String> = None;
    let mut consistent = true;
    for b in branches {
        let Value::Object(m) = b else { return None };
        let s = sanitize_schema(m);
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

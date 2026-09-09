use axum::Json;
use kiro_trust_protocol::catalog;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

/// The shape Claude Code's gateway discovery accepts (spec 5.2), transcribed
/// from kirocc `internal/server/handlers.go` (see NOTICE).
pub async fn get_models() -> Json<Value> {
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let data: Vec<Value> = catalog::list_models()
        .into_iter()
        .map(|m| {
            let mut v =
                json!({"id": m.id, "object": "model", "created": created, "owned_by": "kiro"});
            if let Some(d) = m.display_name {
                v["display_name"] = Value::String(d);
            }
            v
        })
        .collect();
    Json(json!({"object": "list", "data": data}))
}

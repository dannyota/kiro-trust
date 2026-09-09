//! POST /v1/messages/count_tokens: offline estimate (spec 5.7).

use crate::server::error::ApiError;
use crate::server::messages::parse_request;
use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use kiro_trust_protocol::{catalog, estimate};
use serde_json::{Value, json};

pub async fn post_count_tokens(
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let body = body?;
    let req = parse_request(&body)?;
    catalog::resolve(&req.model, false).map_err(|e| ApiError::invalid_request(e.to_string()))?;
    Ok(Json(json!({"input_tokens": estimate::count_tokens(&req)})))
}

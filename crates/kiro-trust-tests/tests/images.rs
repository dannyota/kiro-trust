//! Image validation, limits, and `count_tokens` permissiveness at the HTTP
//! boundary (spec 5.3, 5.5, 5.6, 5.7; 0.2.0 design section 3).

mod common {
    include!("server.rs");
}

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{TOKEN, app, body_string};
use kiro_trust_protocol::eventstream::encode_event_frame;
use kiro_trust_protocol::translate::content::{MAX_IMAGE_BYTES, MAX_IMAGES_PER_REQUEST};
use tower::ServiceExt;

/// Standard base64 of `len` zero bytes, with no crate dependency beyond
/// what `kiro-trust-tests` already has: every 3-byte zero group encodes to
/// `"AAAA"`, and a trailing 1- or 2-byte remainder encodes to `"AA=="` or
/// `"AAA="`.
fn b64_zeros(len: usize) -> String {
    let mut out = String::with_capacity(len.div_ceil(3) * 4);
    for _ in 0..(len / 3) {
        out.push_str("AAAA");
    }
    match len % 3 {
        1 => out.push_str("AA=="),
        2 => out.push_str("AAA="),
        _ => {}
    }
    out
}

fn image_block(media_type: &str, data: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "image",
        "source": {"type": "base64", "media_type": media_type, "data": data}
    })
}

fn messages_req(body: serde_json::Value) -> Request<Body> {
    Request::post("/v1/messages")
        .header("x-api-key", TOKEN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn count_tokens_req(body: serde_json::Value) -> Request<Body> {
    Request::post("/v1/messages/count_tokens")
        .header("x-api-key", TOKEN)
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Every rejected class: 400 `invalid_request_error`, a message naming the
/// specific limit or media type, and zero calls recorded on the scripted
/// upstream (spec 5.3: the 400 is raised before the upstream call starts).
async fn assert_rejected(body: serde_json::Value, expect_in_message: &str) {
    let dir = tempfile::tempdir().unwrap();
    let (app, scripted) = app(dir.path(), vec![]);
    let r = app.oneshot(messages_req(body)).await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let text = body_string(r).await;
    assert!(
        text.contains("\"invalid_request_error\""),
        "expected invalid_request_error: {text}"
    );
    assert!(
        text.contains(expect_in_message),
        "expected message to name {expect_in_message}: {text}"
    );
    assert!(
        scripted.payloads.lock().unwrap().is_empty(),
        "a rejected request must never reach the upstream: {text}"
    );
}

#[tokio::test]
async fn unsupported_media_type_is_rejected_before_the_upstream_call() {
    for media_type in ["image/jpg", "image/svg+xml", ""] {
        assert_rejected(
            serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [
                {"role": "user", "content": [image_block(media_type, &b64_zeros(4))]}
            ]}),
            "image/gif, image/jpeg, image/png, image/webp",
        )
        .await;
    }
}

#[tokio::test]
async fn invalid_base64_is_rejected_before_the_upstream_call() {
    assert_rejected(
        serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [
            {"role": "user", "content": [image_block("image/png", "not-valid-base64!!!")]}
        ]}),
        "base64",
    )
    .await;
}

#[tokio::test]
async fn oversized_image_is_rejected_before_the_upstream_call() {
    let over = b64_zeros(MAX_IMAGE_BYTES + 1);
    assert_rejected(
        serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [
            {"role": "user", "content": [image_block("image/png", &over)]}
        ]}),
        &MAX_IMAGE_BYTES.to_string(),
    )
    .await;
}

#[tokio::test]
async fn exactly_max_images_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let frames = encode_event_frame("assistantResponseEvent", br#"{"content":"ok"}"#);
    let (app, scripted) = app(dir.path(), vec![Ok(frames)]);
    let content: Vec<_> = (0..MAX_IMAGES_PER_REQUEST)
        .map(|_| image_block("image/png", &b64_zeros(4)))
        .collect();
    let r = app
        .oneshot(messages_req(serde_json::json!({
            "model": "claude-sonnet-4-6", "max_tokens": 10, "stream": false,
            "messages": [{"role": "user", "content": content}]
        })))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", body_string(r).await);
    assert_eq!(scripted.payloads.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn eleven_images_is_rejected_before_the_upstream_call() {
    let content: Vec<_> = (0..MAX_IMAGES_PER_REQUEST + 1)
        .map(|_| image_block("image/png", &b64_zeros(4)))
        .collect();
    assert_rejected(
        serde_json::json!({"model": "claude-sonnet-4-6", "max_tokens": 10, "messages": [
            {"role": "user", "content": content}
        ]}),
        &MAX_IMAGES_PER_REQUEST.to_string(),
    )
    .await;
}

/// Spec 5.1, 5.7: `count_tokens` is offline and permissive, never rejecting
/// a request `/v1/messages` would reject.
#[tokio::test]
async fn count_tokens_still_returns_200_for_every_rejected_image_class() {
    let dir = tempfile::tempdir().unwrap();
    let (app, scripted) = app(dir.path(), vec![]);

    for (media_type, data) in [
        ("image/svg+xml", b64_zeros(4)),
        ("image/png", "not-valid-base64!!!".to_string()),
        ("image/png", b64_zeros(MAX_IMAGE_BYTES + 1)),
    ] {
        let r = app
            .clone()
            .oneshot(count_tokens_req(serde_json::json!({
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": [image_block(media_type, &data)]}]
            })))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{}", body_string(r).await);
    }

    let content: Vec<_> = (0..MAX_IMAGES_PER_REQUEST + 1)
        .map(|_| image_block("image/png", &b64_zeros(4)))
        .collect();
    let r = app
        .oneshot(count_tokens_req(serde_json::json!({
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": content}]
        })))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", body_string(r).await);
    assert!(
        scripted.payloads.lock().unwrap().is_empty(),
        "count_tokens never calls the upstream"
    );
}

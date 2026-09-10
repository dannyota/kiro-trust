//! Content extraction from Anthropic blocks. Transcribed from kirocc
//! internal/reqconv/content_text.go, content_scan.go, tool_results.go, images.go.

use crate::anthropic::{ContentBlock, MessageContent, ToolResultContent};
use crate::kiro::{
    HistoryToolUse, Image, ImageSource, TOOL_RESULT_ERROR, TOOL_RESULT_SUCCESS, ToolResult,
    ToolResultContent as KiroResultContent,
};
use base64::Engine;
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

/// Transcribed from the Kiro CLI: the closed `ImageFormat` enum
/// (`amzn-codewhisperer-streaming-client`, `_image_format.rs`) and its
/// `MAX_NUMBER_OF_IMAGES_PER_REQUEST` / `MAX_IMAGE_SIZE_BYTES` constants
/// (spec 5.5).
pub const MAX_IMAGES_PER_REQUEST: usize = 10;
pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const IMAGE_FORMATS: &[&str] = &["gif", "jpeg", "png", "webp"];

/// Every rejection is 400 `invalid_request_error` (spec 5.3, 5.5, 5.6). No
/// variant ever carries encoded data or the decoded bytes of an image:
/// spec 6.4's logging allowlist has no field for one, and an error message
/// built from a variant here can end up in a log line (`ApiError`'s
/// `Display`), so the variants themselves must stay silent about content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    #[error(
        "image media type {media_type} is not one of the accepted formats: image/gif, image/jpeg, image/png, image/webp"
    )]
    UnsupportedMediaType { media_type: String },
    #[error("image data is not valid base64")]
    InvalidBase64,
    #[error("image exceeds the {MAX_IMAGE_BYTES} byte limit: decoded to {decoded_bytes} bytes")]
    TooLarge { decoded_bytes: usize },
    #[error("request exceeds the limit of {MAX_IMAGES_PER_REQUEST} images: {count}")]
    TooMany { count: usize },
}

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

/// Images nested inside one tool result: validated and counted against the
/// request-scoped `counter` exactly like a top-level image (spec 5.3 step
/// 5). A tool result cannot carry an image on the wire, so every promoted
/// image is validated here before the caller decides whether to attach it
/// to a message's `images` field.
fn promote_tool_result_images(
    b: &ContentBlock,
    counter: &mut usize,
) -> Result<Vec<Image>, ImageError> {
    let Some(ToolResultContent::Blocks(inner)) = &b.content else {
        return Ok(vec![]);
    };
    let mut promoted = Vec::new();
    for cb in inner.iter().filter(|cb| cb.kind == "image") {
        if let Some(img) = convert_image(cb, counter)? {
            promoted.push(img);
        }
    }
    Ok(promoted)
}

/// One tool-result block: text (with the promotion notice appended when the
/// result carried images) and the images promoted out of it. Shared by
/// history and current-message scanning (spec 0.2.0 design section 3, "one
/// scan implementation for both").
fn scan_tool_result(
    b: &ContentBlock,
    counter: &mut usize,
) -> Result<(ToolResult, Vec<Image>), ImageError> {
    let mut text = extract_tool_result_text(b);
    let promoted = promote_tool_result_images(b, counter)?;
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
    }
    Ok((tool_result(b, text), promoted))
}

/// All tool-result blocks in `content`, plus every image promoted out of
/// them, validated and counted against the same request-scoped `counter`
/// the caller uses for top-level images.
fn scan_tool_results(
    content: &MessageContent,
    counter: &mut usize,
) -> Result<(Vec<ToolResult>, Vec<Image>), ImageError> {
    let MessageContent::Blocks(blocks) = content else {
        return Ok((vec![], vec![]));
    };
    let mut results = Vec::new();
    let mut images = Vec::new();
    for b in blocks.iter().filter(|b| b.is_tool_result()) {
        let (result, promoted) = scan_tool_result(b, counter)?;
        results.push(result);
        images.extend(promoted);
    }
    Ok((results, images))
}

/// History form: tool-result promotion applies (spec 0.2.0 design section
/// 3), but the caller decides whether to keep the promoted images (today,
/// the FAIL branch of the `history_image_is_accepted` gate discards them
/// and keeps `HistoryUserInputMessage.images` empty; spec 5.3 step 6).
pub fn extract_tool_results(
    content: &MessageContent,
    counter: &mut usize,
) -> Result<(Vec<ToolResult>, Vec<Image>), ImageError> {
    scan_tool_results(content, counter)
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

/// A source whose `type` is not `base64` (a URL) is skipped, not rejected,
/// matching both the Kiro CLI and kirocc (spec 5.3 step 5); a skip never
/// touches `counter`. A `base64` source is validated: media-type suffix,
/// then base64 decoding, then decoded size, then the request-scoped image
/// count. `image/jpg` is rejected rather than mapped to `jpeg`: the Kiro
/// CLI's `ImageFormat` enum has no `jpg` variant, and guessing at intent is
/// how an invalid enum value used to reach the runtime.
pub fn convert_image(b: &ContentBlock, counter: &mut usize) -> Result<Option<Image>, ImageError> {
    let Some(src) = b.source.as_ref() else {
        return Ok(None);
    };
    if src.kind != "base64" {
        return Ok(None);
    }
    let format = src.media_type.rsplit('/').next().unwrap_or("").to_string();
    if !IMAGE_FORMATS.contains(&format.as_str()) {
        return Err(ImageError::UnsupportedMediaType {
            media_type: src.media_type.clone(),
        });
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&src.data)
        .map_err(|_| ImageError::InvalidBase64)?;
    if decoded.len() > MAX_IMAGE_BYTES {
        return Err(ImageError::TooLarge {
            decoded_bytes: decoded.len(),
        });
    }
    *counter += 1;
    if *counter > MAX_IMAGES_PER_REQUEST {
        return Err(ImageError::TooMany { count: *counter });
    }
    Ok(Some(Image {
        format,
        source: ImageSource {
            bytes: src.data.clone(),
        },
    }))
}

pub struct Scanned {
    pub tool_results: Vec<ToolResult>,
    pub images: Vec<Image>,
}

/// Current-message form: images nested in tool results are promoted to the
/// message and noted in stdout (kirocc `scanCurrentMessage`), validated and
/// counted against the same request-scoped `counter` as top-level images.
pub fn scan_current_message(
    content: &MessageContent,
    counter: &mut usize,
) -> Result<Scanned, ImageError> {
    let mut out = Scanned {
        tool_results: vec![],
        images: vec![],
    };
    let MessageContent::Blocks(blocks) = content else {
        return Ok(out);
    };
    for b in blocks {
        if b.is_tool_result() {
            let (result, promoted) = scan_tool_result(b, counter)?;
            out.images.extend(promoted);
            out.tool_results.push(result);
        } else if b.kind == "image"
            && let Some(img) = convert_image(b, counter)?
        {
            out.images.push(img);
        }
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::ContentBlock;
    use serde_json::json;

    fn image_block(media_type: &str, data: &str) -> ContentBlock {
        serde_json::from_value(json!({
            "type": "image",
            "source": {"type": "base64", "media_type": media_type, "data": data}
        }))
        .unwrap()
    }

    fn url_image_block() -> ContentBlock {
        serde_json::from_value(json!({
            "type": "image",
            "source": {"type": "url", "url": "https://example.com/x.png"}
        }))
        .unwrap()
    }

    // Transcribed formats: gif, jpeg, png, webp (spec 5.5, Kiro CLI
    // `ImageFormat`).
    #[test]
    fn all_four_accepted_media_types_decode() {
        let mut counter = 0usize;
        for (media_type, format) in [
            ("image/gif", "gif"),
            ("image/jpeg", "jpeg"),
            ("image/png", "png"),
            ("image/webp", "webp"),
        ] {
            let b = image_block(media_type, "AAAA");
            let img = convert_image(&b, &mut counter).unwrap().unwrap();
            assert_eq!(img.format, format);
            assert_eq!(img.source.bytes, "AAAA");
        }
        assert_eq!(counter, 4);
    }

    #[test]
    fn image_jpg_is_rejected_not_mapped_to_jpeg() {
        let mut counter = 0usize;
        let b = image_block("image/jpg", "AAAA");
        let err = convert_image(&b, &mut counter).map(|_| ()).unwrap_err();
        assert_eq!(
            err,
            ImageError::UnsupportedMediaType {
                media_type: "image/jpg".into()
            }
        );
        assert_eq!(counter, 0, "a rejected image never counts");
    }

    #[test]
    fn svg_media_type_is_rejected() {
        let mut counter = 0usize;
        let b = image_block("image/svg+xml", "AAAA");
        let err = convert_image(&b, &mut counter).map(|_| ()).unwrap_err();
        assert_eq!(
            err,
            ImageError::UnsupportedMediaType {
                media_type: "image/svg+xml".into()
            }
        );
    }

    #[test]
    fn empty_media_type_is_rejected() {
        let mut counter = 0usize;
        let b = image_block("", "AAAA");
        let err = convert_image(&b, &mut counter).map(|_| ()).unwrap_err();
        assert_eq!(
            err,
            ImageError::UnsupportedMediaType {
                media_type: "".into()
            }
        );
    }

    #[test]
    fn invalid_base64_is_rejected() {
        let mut counter = 0usize;
        let b = image_block("image/png", "not-valid-base64!!!");
        assert_eq!(
            convert_image(&b, &mut counter).map(|_| ()).unwrap_err(),
            ImageError::InvalidBase64
        );
    }

    #[test]
    fn exactly_max_bytes_is_accepted_one_byte_over_is_rejected() {
        let mut counter = 0usize;
        let at_limit = base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_IMAGE_BYTES]);
        let b = image_block("image/png", &at_limit);
        assert!(convert_image(&b, &mut counter).unwrap().is_some());

        let mut counter = 0usize;
        let over_limit =
            base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_IMAGE_BYTES + 1]);
        let b = image_block("image/png", &over_limit);
        assert_eq!(
            convert_image(&b, &mut counter).map(|_| ()).unwrap_err(),
            ImageError::TooLarge {
                decoded_bytes: MAX_IMAGE_BYTES + 1
            }
        );
    }

    #[test]
    fn exactly_max_images_is_accepted_one_more_is_rejected() {
        let mut counter = 0usize;
        for _ in 0..MAX_IMAGES_PER_REQUEST {
            let b = image_block("image/png", "AAAA");
            assert!(convert_image(&b, &mut counter).unwrap().is_some());
        }
        let b = image_block("image/png", "AAAA");
        assert_eq!(
            convert_image(&b, &mut counter).map(|_| ()).unwrap_err(),
            ImageError::TooMany {
                count: MAX_IMAGES_PER_REQUEST + 1
            }
        );
    }

    #[test]
    fn non_base64_source_is_skipped_not_rejected_and_does_not_count() {
        let mut counter = 0usize;
        let b = url_image_block();
        assert!(convert_image(&b, &mut counter).unwrap().is_none());
        assert_eq!(counter, 0);
    }

    #[test]
    fn nested_tool_result_promotion_writes_notice_and_counts() {
        let mut counter = 0usize;
        let content: MessageContent = serde_json::from_value(json!([
            {"type": "tool_result", "tool_use_id": "t1", "content": [
                {"type": "text", "text": "ran ok"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}
            ]}
        ]))
        .unwrap();
        let scanned = scan_current_message(&content, &mut counter).unwrap();
        assert_eq!(scanned.images.len(), 1);
        assert_eq!(scanned.tool_results.len(), 1);
        let json_val = scanned.tool_results[0].content[0].json.as_ref().unwrap();
        assert_eq!(
            json_val["stdout"],
            "ran ok\n[1 image(s) from this tool result attached to the message]"
        );
        assert_eq!(counter, 1);
    }

    #[test]
    fn history_tool_result_promotion_writes_same_notice() {
        let mut counter = 0usize;
        let content: MessageContent = serde_json::from_value(json!([
            {"type": "tool_result", "tool_use_id": "t1", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}
            ]}
        ]))
        .unwrap();
        let (results, images) = extract_tool_results(&content, &mut counter).unwrap();
        assert_eq!(images.len(), 1);
        let json_val = results[0].content[0].json.as_ref().unwrap();
        assert_eq!(
            json_val["stdout"],
            "[1 image(s) from this tool result attached to the message]"
        );
    }

    #[test]
    fn counter_spans_history_and_current_message() {
        // One shared counter across two scans, as `build_payload` will use
        // it: history exhausts the limit, current message's own image (or
        // a promoted one) is the rejection.
        let mut counter = 0usize;
        for _ in 0..MAX_IMAGES_PER_REQUEST {
            let b = image_block("image/png", "AAAA");
            convert_image(&b, &mut counter).unwrap();
        }
        let b = image_block("image/png", "AAAA");
        assert_eq!(
            convert_image(&b, &mut counter).map(|_| ()).unwrap_err(),
            ImageError::TooMany {
                count: MAX_IMAGES_PER_REQUEST + 1
            }
        );
    }
}

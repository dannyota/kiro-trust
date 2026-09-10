//! Deterministic, offline `count_tokens` estimate (spec 5.7).

use crate::anthropic::{ContentBlock, MessageContent, Request, ToolResultContent};
use base64::Engine;

/// `ceil(decoded_bytes / 750)` for one image source, or 0 for anything that
/// is not a valid base64 image: `count_tokens` applies no media-type, size,
/// or count rejection (spec 5.1, 5.7), unlike `/v1/messages`'s validation
/// in `translate::content`. A non-`base64` source (a URL) and invalid
/// base64 both contribute zero, matching "as rough as the rest of the
/// estimate" rather than erroring.
fn image_tokens(b: &ContentBlock) -> u64 {
    let Some(src) = b.source.as_ref() else {
        return 0;
    };
    if src.kind != "base64" {
        return 0;
    }
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&src.data) else {
        return 0;
    };
    decoded.len().div_ceil(750) as u64
}

pub fn count_tokens(req: &Request) -> u64 {
    let mut bytes = req.system_text().len();
    let mut image_tok = 0u64;
    for m in &req.messages {
        match &m.content {
            MessageContent::Text(t) => bytes += t.len(),
            MessageContent::Blocks(blocks) => {
                for b in blocks {
                    if let Some(t) = &b.text {
                        bytes += t.len();
                    }
                    if let Some(t) = &b.thinking {
                        bytes += t.len();
                    }
                    if let Some(input) = &b.input {
                        bytes += input.to_string().len();
                    }
                    if b.kind == "image" {
                        image_tok += image_tokens(b);
                    }
                    match &b.content {
                        Some(ToolResultContent::Text(t)) => bytes += t.len(),
                        Some(ToolResultContent::Blocks(inner)) => {
                            bytes += inner
                                .iter()
                                .filter_map(|c| c.text.as_ref())
                                .map(String::len)
                                .sum::<usize>();
                            image_tok += inner
                                .iter()
                                .filter(|c| c.kind == "image")
                                .map(image_tokens)
                                .sum::<u64>();
                        }
                        None => {}
                    }
                }
            }
        }
    }
    for t in &req.tools {
        bytes += serde_json::to_string(t).map(|s| s.len()).unwrap_or(0);
    }
    bytes.div_ceil(4) as u64 + 3 * req.messages.len() as u64 + image_tok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::Request;
    use serde_json::json;

    #[test]
    fn estimate_is_deterministic_and_counts_every_text_source() {
        let r: Request = serde_json::from_value(json!({"model": "m", "max_tokens": 1, "system": "abcd",
            "tools": [{"name": "T", "description": "dddd", "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": "abcdefgh"},
                         {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "T", "input": {"k": "vvvv"}}]},
                         {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "rrrr"}]}]})).unwrap();
        let n = count_tokens(&r);
        assert_eq!(n, count_tokens(&r));
        assert!(
            n >= 3 * 3 + (4 + 8 + 4) / 4,
            "at least the per-message constant plus visible text"
        );
        let empty: Request = serde_json::from_value(
            json!({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": ""}]}),
        )
        .unwrap();
        assert_eq!(count_tokens(&empty), 3);
    }

    fn image_request(media_type: &str, data: &str) -> Request {
        serde_json::from_value(json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": ""},
                {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": data}}
            ]}
        ]}))
        .unwrap()
    }

    fn without_image(req: &Request) -> u64 {
        let mut r = req.clone();
        if let MessageContent::Blocks(blocks) = &mut r.messages[0].content {
            blocks.retain(|b| b.kind != "image");
        }
        count_tokens(&r)
    }

    // spec 5.7: `ceil(decoded_bytes / 750)`, rounding at the boundary.
    #[test]
    fn image_term_rounds_up_at_1_750_and_751_decoded_bytes() {
        use base64::Engine;
        let enc = base64::engine::general_purpose::STANDARD;
        for (decoded_bytes, expected_image_tokens) in [(1usize, 1u64), (750, 1), (751, 2)] {
            let data = enc.encode(vec![0u8; decoded_bytes]);
            let r = image_request("image/png", &data);
            let base = without_image(&r);
            assert_eq!(
                count_tokens(&r) - base,
                expected_image_tokens,
                "decoded_bytes={decoded_bytes}"
            );
        }
    }

    // spec 5.1, 5.7: count_tokens applies no image validation or limits, and
    // still returns 200 (never a `Result`) for every request `/v1/messages`
    // would reject.
    #[test]
    fn count_tokens_stays_permissive_for_every_rejected_image_class() {
        // Unsupported media type is not gated at all here: the byte term
        // still applies, matching how `/v1/messages` rejection has no
        // effect on this endpoint.
        let r = image_request("image/svg+xml", "AAAA");
        assert_eq!(count_tokens(&r) - without_image(&r), 1);

        // Invalid base64 contributes zero: it cannot be measured at all.
        let r = image_request("image/png", "not-valid-base64!!!");
        assert_eq!(count_tokens(&r) - without_image(&r), 0);

        // Oversized (over MAX_IMAGE_BYTES) is still just its rounded byte
        // count: no rejection, no ceiling applied here.
        use base64::Engine;
        let big = base64::engine::general_purpose::STANDARD.encode(vec![
            0u8;
            crate::translate::content::MAX_IMAGE_BYTES
                + 1
        ]);
        let r = image_request("image/png", &big);
        assert_eq!(
            count_tokens(&r) - without_image(&r),
            ((crate::translate::content::MAX_IMAGE_BYTES + 1) as u64).div_ceil(750)
        );

        // 11 images (over MAX_IMAGES_PER_REQUEST) each contribute their own
        // term; no count limit applies.
        let image_block = json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}});
        let content: Vec<_> = std::iter::repeat_n(image_block, 11).collect();
        let req: Request =
            serde_json::from_value(json!({"model": "m", "max_tokens": 1, "messages": [
                {"role": "user", "content": content}
            ]}))
            .unwrap();
        assert_eq!(count_tokens(&req), 11 + 3);
    }
}

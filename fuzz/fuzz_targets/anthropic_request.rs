#![no_main]
use kiro_trust_protocol::anthropic::Request;
use kiro_trust_protocol::estimate::count_tokens;
use kiro_trust_protocol::translate::request::{BuildOptions, build_payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(req) = serde_json::from_slice::<Request>(data) else {
        return;
    };
    let _ = count_tokens(&req);
    // `build_payload` is fallible since 0.2.0: an image with an unsupported
    // media type, undecodable base64, an oversized decoded body, or too many
    // images per request is a rejection, not a panic (spec 5.3, 5.5). A
    // rejection is a valid outcome for arbitrary input, so the fuzzer treats
    // it as uninteresting and returns; what it still asserts is that an
    // accepted payload always serializes.
    let Ok(built) = build_payload(
        &req,
        &BuildOptions {
            profile_arn: Some("arn:test".into()),
            model_id: "m".into(),
            conversation_id: None,
            effort: None,
        },
    ) else {
        return;
    };
    serde_json::to_vec(&built.payload).expect("payload serializes");
});

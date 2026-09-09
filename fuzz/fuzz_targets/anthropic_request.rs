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
    let built = build_payload(
        &req,
        &BuildOptions {
            profile_arn: Some("arn:test".into()),
            model_id: "m".into(),
            conversation_id: None,
            effort: None,
        },
    );
    serde_json::to_vec(&built.payload).expect("payload serializes");
});

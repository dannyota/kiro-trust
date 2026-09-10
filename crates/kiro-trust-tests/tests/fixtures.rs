//! Every directory under tests/fixtures is one case (spec 8.2). Set
//! UPDATE_FIXTURES=1 to (re)generate expected files, then review the diff.

use kiro_trust_protocol::anthropic::Request;
use kiro_trust_protocol::catalog;
use kiro_trust_protocol::eventstream::{EventParser, FrameDecoder};
use kiro_trust_protocol::sse;
use kiro_trust_protocol::translate::request::{BuildOptions, build_payload};
use kiro_trust_protocol::translate::response::{ResponseOptions, ResponseTranslator};
use kiro_trust_tests::{
    FIXTURE_ARN, FIXTURE_CONVERSATION_ID, FIXTURE_MESSAGE_ID, fixtures_dir, load_upstream_frames,
    mask_message_ids,
};
use std::path::Path;

fn update() -> bool {
    std::env::var_os("UPDATE_FIXTURES").is_some()
}

fn check(path: &Path, actual: &str) {
    if update() {
        std::fs::write(path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("missing {}; run with UPDATE_FIXTURES=1", path.display()));
    assert_eq!(actual, expected, "{} differs", path.display());
}

fn run_case(case: &Path) {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(case.join("meta.json")).unwrap()).unwrap();
    assert!(meta["source"].is_string(), "meta.json needs a source");
    let req: Request =
        serde_json::from_slice(&std::fs::read(case.join("request.json")).unwrap()).unwrap();
    let resolved = catalog::resolve(&req.model, false).unwrap();
    let effort = catalog::resolve_effort(
        &resolved,
        req.effort(),
        req.thinking_enabled() || resolved.thinking,
    );
    let built = build_payload(
        &req,
        &BuildOptions {
            profile_arn: Some(FIXTURE_ARN.into()),
            model_id: resolved.kiro_model.clone(),
            conversation_id: Some(FIXTURE_CONVERSATION_ID.into()),
            effort,
        },
    )
    .unwrap();
    let payload = serde_json::to_string_pretty(&built.payload).unwrap() + "\n";
    check(&case.join("expected-payload.json"), &payload);

    let Some(bytes) = load_upstream_frames(case) else {
        return;
    };
    let mut decoder = FrameDecoder::new();
    let mut parser = EventParser::new();
    let mut translator = ResponseTranslator::new(ResponseOptions {
        model: resolved.anthropic_model.clone(),
        message_id: FIXTURE_MESSAGE_ID.into(),
        stop_sequences: req.stop_sequences.clone(),
        max_tokens: req.max_tokens,
        tool_names: built.tool_names.reverse_map(),
        estimated_input_tokens: 0,
    });
    decoder.push(&bytes);
    let mut out = String::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        for ev in parser.parse(&frame).unwrap() {
            for s in translator.push(&ev) {
                out.push_str(&sse::encode(&s));
            }
        }
    }
    decoder.finish().unwrap();
    if let Some(ev) = parser.finish() {
        for s in translator.push(&ev) {
            out.push_str(&sse::encode(&s));
        }
    }
    for s in translator.finish() {
        out.push_str(&sse::encode(&s));
    }
    if req.stream {
        check(&case.join("expected-sse.txt"), &mask_message_ids(&out));
    } else {
        let msg = serde_json::to_string_pretty(&translator.into_message()).unwrap() + "\n";
        check(&case.join("expected-message.json"), &msg);
    }
}

#[test]
fn every_fixture_case() {
    let mut cases: Vec<_> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir() && e.path().join("request.json").exists())
        .map(|e| e.path())
        .collect();
    cases.sort();
    assert!(!cases.is_empty(), "no fixture cases found");
    for case in cases {
        run_case(&case);
    }
}

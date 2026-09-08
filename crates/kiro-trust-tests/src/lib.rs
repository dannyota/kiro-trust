//! Support for fixture, security, server, and live tests. Not published.

use kiro_trust_protocol::eventstream::{encode_event_frame, encode_exception_frame};
use std::path::{Path, PathBuf};

pub const FIXTURE_ARN: &str = "arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE";
pub const FIXTURE_CONVERSATION_ID: &str = "00000000-0000-4000-8000-00000000c0ff";
pub const FIXTURE_MESSAGE_ID: &str = "msg_fixture000000000000000";

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

pub fn fixtures_dir() -> PathBuf {
    workspace_root().join("tests/fixtures")
}

/// Upstream bytes for a case: `upstream.eventstream` (raw capture) or
/// `upstream.events.json`, a list of `{"event_type": .., "payload": ..}` or
/// `{"exception_type": .., "payload": ..}` objects, one frame each.
pub fn load_upstream_frames(case: &Path) -> Option<Vec<u8>> {
    let raw = case.join("upstream.eventstream");
    if raw.exists() {
        return Some(std::fs::read(raw).unwrap());
    }
    let json = case.join("upstream.events.json");
    if !json.exists() {
        return None;
    }
    let events: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(json).unwrap()).unwrap();
    let mut out = Vec::new();
    for e in events {
        let payload = serde_json::to_vec(&e["payload"]).unwrap();
        if let Some(t) = e.get("exception_type").and_then(|v| v.as_str()) {
            out.extend(encode_exception_frame(t, &payload));
        } else {
            out.extend(encode_event_frame(
                e["event_type"].as_str().unwrap(),
                &payload,
            ));
        }
    }
    Some(out)
}

/// Replace `msg_` ids so captured and generated output compare.
pub fn mask_message_ids(sse: &str) -> String {
    let mut out = String::with_capacity(sse.len());
    let mut rest = sse;
    while let Some(i) = rest.find("\"msg_") {
        out.push_str(&rest[..i]);
        out.push_str("\"msg_MASKED\"");
        let after = &rest[i + 1..];
        let end = after.find('"').map(|e| e + 1).unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

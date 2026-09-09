#![no_main]
use arbitrary::Arbitrary;
use kiro_trust_protocol::eventstream::{EventParser, FrameDecoder, encode_event_frame};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Frag {
    id: Option<u8>,
    name: Option<String>,
    input_string: Option<String>,
    input_object: bool,
    stop: Option<bool>,
}

fuzz_target!(|frags: Vec<Frag>| {
    let mut d = FrameDecoder::new();
    let mut p = EventParser::new();
    for f in frags.into_iter().take(256) {
        let mut v = serde_json::Map::new();
        if let Some(id) = f.id {
            v.insert(
                "toolUseId".into(),
                serde_json::Value::String(format!("t{id}")),
            );
        }
        if let Some(n) = f.name {
            v.insert("name".into(), serde_json::Value::String(n));
        }
        if f.input_object {
            v.insert("input".into(), serde_json::json!({"k": 1}));
        } else if let Some(s) = f.input_string {
            v.insert("input".into(), serde_json::Value::String(s));
        }
        if let Some(s) = f.stop {
            v.insert("stop".into(), serde_json::Value::Bool(s));
        }
        d.push(&encode_event_frame(
            "toolUseEvent",
            &serde_json::to_vec(&v).unwrap(),
        ));
        while let Ok(Some(frame)) = d.next_frame() {
            let _ = p.parse(&frame);
        }
    }
    let _ = p.finish();
});

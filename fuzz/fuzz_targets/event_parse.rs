#![no_main]
use arbitrary::Arbitrary;
use kiro_trust_protocol::eventstream::{
    EventParser, FrameDecoder, encode_event_frame, encode_exception_frame,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    frames: Vec<(bool, String, Vec<u8>)>,
}

fuzz_target!(|input: Input| {
    let mut d = FrameDecoder::new();
    let mut p = EventParser::new();
    for (exception, name, payload) in input.frames.into_iter().take(64) {
        let name: String = name.chars().take(200).collect();
        let bytes = if exception {
            encode_exception_frame(&name, &payload)
        } else {
            encode_event_frame(&name, &payload)
        };
        d.push(&bytes);
        while let Ok(Some(f)) = d.next_frame() {
            let _ = p.parse(&f);
        }
    }
    let _ = p.finish();
});

#![no_main]
use kiro_trust_protocol::eventstream::{FrameDecoder, MAX_FRAME_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut d = FrameDecoder::new();
    for chunk in data.chunks(13) {
        d.push(chunk);
        loop {
            match d.next_frame() {
                Ok(Some(f)) => assert!(f.payload.len() + f.headers.len() * 2 <= MAX_FRAME_BYTES),
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
    let _ = d.finish();
});

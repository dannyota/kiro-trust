#![no_main]
use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use kiro_trust_protocol::eventstream::{FrameDecoder, HeaderValue, encode_frame, push_header};
use libfuzzer_sys::fuzz_target;

/// One eventstream header. `name` and the `Bytes`/`String` variants are
/// capped in `encode` so the u8/u16 length prefixes `push_header` writes
/// never wrap.
#[derive(Arbitrary, Debug)]
struct GenHeader {
    name: String,
    value: GenValue,
}

#[derive(Arbitrary, Debug)]
enum GenValue {
    Bool(bool),
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Bytes(Vec<u8>),
    String(String),
    Timestamp(i64),
    Uuid([u8; 16]),
}

impl GenHeader {
    fn encode(self, buf: &mut Vec<u8>) {
        let name: String = self.name.chars().take(20).collect();
        let value = match self.value {
            GenValue::Bool(b) => HeaderValue::Bool(b),
            GenValue::Byte(b) => HeaderValue::Byte(b),
            GenValue::Short(s) => HeaderValue::Short(s),
            GenValue::Int(i) => HeaderValue::Int(i),
            GenValue::Long(l) => HeaderValue::Long(l),
            GenValue::Bytes(mut b) => {
                b.truncate(2000);
                HeaderValue::Bytes(b)
            }
            GenValue::String(s) => HeaderValue::String(s.chars().take(500).collect()),
            GenValue::Timestamp(t) => HeaderValue::Timestamp(t),
            GenValue::Uuid(u) => HeaderValue::Uuid(u),
        };
        push_header(buf, &name, &value);
    }
}

/// A frame built through the crate's own encoder rather than raw bytes, so
/// mutation explores header combinations and multi-frame reassembly
/// instead of guessing two independent CRC32 values (fix-1 Critical 2).
#[derive(Arbitrary, Debug)]
struct GenFrame {
    headers: Vec<GenHeader>,
    payload: Vec<u8>,
}

impl GenFrame {
    fn encode(self) -> Vec<u8> {
        let mut headers = Vec::new();
        for h in self.headers.into_iter().take(16) {
            h.encode(&mut headers);
        }
        let mut payload = self.payload;
        payload.truncate(4096);
        encode_frame(&headers, &payload)
    }
}

#[derive(Arbitrary, Debug)]
struct Structured {
    frames: Vec<GenFrame>,
    /// Fuzzer-chosen (index, xor byte) so the malformed-frame paths stay
    /// reachable even from an otherwise structurally valid stream.
    corrupt: Option<(u32, u8)>,
    /// Bytes to drop from the end of the encoded stream, so the
    /// `finish()` truncation path stays reachable too.
    truncate: Option<u16>,
}

/// `Raw` keeps fully unstructured bytes reachable: some malformed shapes
/// (a total/headers-length mismatch, bytes that never form a valid prelude
/// at all) are easier for pure mutation to stumble into than for the
/// structured generator above to construct on purpose.
#[derive(Debug)]
enum Mode {
    Structured(Structured),
    Raw(Vec<u8>),
}

impl<'a> Arbitrary<'a> for Mode {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        // 7-in-8 so most runs exercise real framing; Raw stays available
        // for shapes structured generation can't easily hit.
        if u.ratio(7u8, 8u8)? {
            Ok(Mode::Structured(Structured::arbitrary(u)?))
        } else {
            Ok(Mode::Raw(Vec::<u8>::arbitrary(u)?))
        }
    }
}

fn build_stream(mode: Mode) -> Vec<u8> {
    match mode {
        Mode::Raw(bytes) => bytes,
        Mode::Structured(s) => {
            let mut bytes = Vec::new();
            for f in s.frames.into_iter().take(8) {
                bytes.extend(f.encode());
            }
            if let Some((idx, xor)) = s.corrupt
                && !bytes.is_empty()
            {
                let idx = idx as usize % bytes.len();
                bytes[idx] ^= xor;
            }
            if let Some(n) = s.truncate {
                let n = (n as usize).min(bytes.len());
                bytes.truncate(bytes.len() - n);
            }
            bytes
        }
    }
}

fuzz_target!(|mode: Mode| {
    let data = build_stream(mode);
    let mut d = FrameDecoder::new();
    let mut pushed = 0usize;
    let mut consumed = 0usize;
    for chunk in data.chunks(13) {
        d.push(chunk);
        pushed += chunk.len();
        loop {
            match d.next_frame() {
                Ok(Some(f)) => {
                    // Real round trip in place of the tautological bound
                    // (fix-1 minor 1): re-encode the decoded frame and
                    // check it accounts for exactly the bytes the decoder
                    // reports consumed.
                    let mut headers = Vec::new();
                    for (name, value) in &f.headers {
                        push_header(&mut headers, name, value);
                    }
                    consumed += encode_frame(&headers, &f.payload).len();
                    assert_eq!(pushed - d.pending(), consumed);
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
    let _ = d.finish();
});

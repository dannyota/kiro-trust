# kiro-trust 0.2.0 — design

Status: approved 2026-09-09. Scope for the 0.2.0 release.
`kiro-trust-design.md` in this directory remains the source of truth; this
document records the reasoning behind the 0.2.0 amendments to it and is not a
second authority. Where the two disagree, that spec wins.

## 1. Scope

Six changes. Three concern images, two add command surface, one replaces the
listener.

| # | Change | Crates |
| --- | --- | --- |
| 1 | Validate image `format` against the Kiro enum; 400 otherwise | protocol |
| 2 | Enforce 10 images per request and 10 MB per image; 400 naming the limit | protocol, kiro-trust |
| 3 | Send images in history entries, gated on a live test | protocol |
| 4 | `kiro-trust exec -- <cmd>` | kiro-trust |
| 5 | `--extra-ca <pem>` | net, kiro-trust |
| 6 | Header read timeout and idle connection cap | kiro-trust |

Retry of thinking-only responses stays deferred. It needs buffered SSE, and the
spec requires measuring how often Kiro returns no visible text before building
it. Change 3's live tests are the first chance to measure; the implementation
reports a count and does not act on it.

Four backlog items are closed as decided-no rather than deferred: proxy-side
Tool Search, `models sync`, social login, and Kiro API keys. `CLAUDE.md`
forbids porting each, and each would add a trust boundary (a second credential
type) or a new outbound host, which spec 6.2 and 6.5 rule out. Removing them
from the backlog stops that table implying they are scheduled.

## 2. Oracle

`aws/amazon-q-developer-cli` (Apache-2.0) is the Kiro CLI's upstream. It vendors
the Smithy-generated SDK for the same runtime kiro-trust calls, so for wire
shape it outranks kirocc, which was reverse engineered. Both are references
only; neither is vendored. Transcribed rules are recorded here and in the
project spec, and the files are listed in `NOTICE`.

Facts this design rests on, read from the generated SDK at commit `15cc8f3`:

- `ImageFormat` is a closed enum: `gif`, `jpeg`, `png`, `webp`. There is no
  `jpg` variant. (`crates/amzn-codewhisperer-streaming-client/src/types/_image_format.rs`)
- `ImageSource` is a union with one `bytes` variant, base64 on the wire.
  (`.../types/_image_source.rs`, `.../protocol_serde/shape_image_source.rs`)
- `ConversationState.history` is `Vec<ChatMessage>`, and
  `ChatMessage::UserInputMessage` is the same `UserInputMessage` type that
  carries `images`. History images are therefore representable.
  (`.../types/_chat_message.rs`, `.../types/_user_input_message.rs`)
- The shipped `chat` path sends them: `into_history_entry()` sets
  `images: self.images.clone()`, and the SDK conversion calls `.set_images()`
  on the history builder unconditionally.
  (`crates/chat-cli/src/cli/chat/message.rs`, `crates/chat-cli/src/api_client/model.rs`)
- The newer `agent` path hardcodes `images: None` for history, matching kirocc.
  Its comment explains only that tool results cannot carry an image, not that
  history cannot. (`crates/chat-cli/src/agent/rts/mod.rs`)
- Limits: 10 MB per image, 10 images per request.
  (`crates/chat-cli/src/cli/chat/consts.rs`, `crates/agent/src/agent/consts.rs`)

The two upstream paths disagree about history images, so the SDK proves the
field exists but not that the runtime accepts it. Change 3 resolves that by
test, not by reading more code.

## 3. Image validation and limits

`convert_image` currently returns `Option<Image>` and discards the reason for
every rejection. It becomes fallible with a reason, because the caller must now
tell "this block is not an image" apart from "this image must be rejected".

New constants in `kiro-trust-protocol`, transcribed from the Kiro CLI:

```rust
pub const MAX_IMAGES_PER_REQUEST: usize = 10;
pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const IMAGE_FORMATS: &[&str] = &["gif", "jpeg", "png", "webp"];
```

Four rejections, each 400 `invalid_request_error` (spec 5.6):

1. A `media_type` whose suffix is not in `IMAGE_FORMATS`. The message names the
   received media type and the four accepted ones. `image/jpg` is rejected
   rather than mapped to `jpeg`: guessing at a caller's intent is how an
   invalid enum value reaches the runtime, which is the defect this change
   fixes.
2. Base64 that does not decode.
3. A decoded length over `MAX_IMAGE_BYTES`. The limit is on decoded bytes, not
   on the base64 text, because upstream measures file size.
4. More than `MAX_IMAGES_PER_REQUEST` images across the request, counting
   images promoted out of tool results.

Anthropic's documented media types (`image/jpeg`, `image/png`, `image/gif`,
`image/webp`) map onto the enum exactly, so a well-formed request is
unaffected. The rejections catch `image/svg+xml`, `image/heic`, `image/jpg`,
and an empty media type, each of which today reaches the runtime as an invalid
enum value and returns an opaque upstream error.

A non-`base64` source (a URL) is skipped, not rejected, matching both oracles.
The skip becomes explicit and tested rather than incidental. Nothing is logged
for any of these: spec 6.4's allowlist has no field for an image, and this
change does not add one.

The checks live in the `/v1/messages` handler, alongside `MAX_MESSAGES` and
`MAX_TOOLS`, so `count_tokens` stays permissive (spec 5.1).

`count_tokens` gains image accounting: decoded byte length divided by 750,
documented as approximate like the rest of spec 5.7. Today an image
contributes zero, so a 5 MB paste estimates as nothing, which makes the
endpoint misleading rather than merely rough.

## 4. History images

Two steps. The second happens only if the first passes.

**Step one, evidence.** A live test, `history_image_is_accepted`, `#[ignore]`d
and gated on `KIRO_TRUST_LIVE=1` like its siblings (spec 8.6). It sends three
messages (user with a small synthetic PNG, assistant reply, user follow-up) so
the image lands in a history entry, and asserts a 200 with a well-formed
stream. It asserts structure only, never model wording, and prints counts and
durations only.

**Step two, implementation, only on success.** `HistoryUserInputMessage` gains
`images: Vec<Image>` with `skip_serializing_if = "Vec::is_empty"`, and
`build_history` scans for images the way the current message already does.
Tool-result promotion applies in history too, since the restriction that a
tool result cannot carry an image is not specific to the current turn.

If the live test fails, change 3 ships as a spec note recording that the
runtime rejects history images, with the live test retained as the evidence.
That is a useful outcome, and it is why the test comes first: shipping an
unverified field would break every multi-turn request that ever contained an
image.

## 5. `exec` and `--extra-ca`

`kiro-trust exec -- <cmd> [args...]` reads the token file, validates the token
against the shape `token::generate` produces exactly as `env` does (spec 4.3),
then runs the child with `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` in its
environment and nothing else changed. The token never reaches a shell, a log,
or an error path, which is the point: it is `env` without the shell round trip.

This adds a sixth `expose_secret()` site to the enumerated list in `CLAUDE.md`
and spec 6.2, with the same justification `env` carries: handing the token to
the child process is the command's whole purpose, and there is no way to
implement it without one. On Unix it `exec`s, so no wrapper process lingers;
elsewhere it spawns and forwards the child's exit code.

`--extra-ca <pem>` adds one PEM file to the compiled `webpki-roots` set in
`kiro-trust-net`, additively. It never replaces the compiled roots,
`SSL_CERT_FILE` stays ignored (spec 6.2), and `audit` gains a line showing the
path so the deviation is visible (spec 6.6). A malformed PEM is a
configuration error at startup, never a silent fallback to the default roots.

## 6. Header read timeout and connection cap

A `GuardedListener` wrapping `TcpListener` and implementing axum 0.8's
`Listener` trait. `accept` takes a semaphore permit before accepting, so at
`MAX_CONNECTIONS` the process stops accepting rather than accepting and
dropping. The trait's `accept` cannot return an error, so backpressure has to
work by not accepting; that shape is why the semaphore sits before the accept
call and not after it.

`Listener::Io` becomes a wrapper holding the `TcpStream`, the permit, and a
deadline. The permit releases when the wrapper drops. From accept, the wrapper
fails the connection if no write has been attempted within
`HEADER_READ_TIMEOUT` (15 s). The server writes only after parsing a complete
request, so first-write is a sound proxy for "request received", and a client
trickling header bytes trips the deadline. Once a write happens the deadline is
disarmed, so a streaming response runs unbounded, as it must.

`ListenerExt::tap_io` cannot do this: it lends `&mut Io` and cannot substitute
a wrapper type. A hand-written `Listener` impl is required.

`axum::serve` and the shutdown path stay untouched. That is deliberate: the
drain ordering, the token-file deletion before the drain, and the deadline task
that exits 0 are load-bearing and commented as such in
`crates/kiro-trust/src/serve.rs`. This deviates from the backlog's suggested
`hyper_util` accept loop, which would require rebuilding and re-reviewing all
of it; the backlog entry is replaced by a spec section describing what shipped.

One detail is unverified and gets confirmed before implementation: whether an
`Io` wrapper returning an error from `poll_write` cleanly terminates the
connection in axum 0.8.9's hyper integration, or whether the signal has to come
through `poll_read`. That decides a detail of the wrapper, not the approach.

## 7. Testing and review

Per change: unit tests in `kiro-trust-protocol` for every validation branch, a
server test per 400, and a recorded fixture only where a capture is needed
(change 3 may warrant one, recorded per spec 8.3 with a marker prompt and
scrubbed). `security_logging.rs` gains a case asserting that no image bytes,
media type, or count reaches a log line. The full gate list in `CLAUDE.md` runs
before each merge.

Changes 4, 5, and 6 touch the local token, the network policy, and the
listener, so each needs independent adversarial review at the planning-role
model. Changes 1 through 3 need ordinary independent code review. An agent that
designs or reviews a slice does not implement that slice.

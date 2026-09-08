# kiro-trust — design

Status: approved design for v0.1. This document is the source of truth for
scope, architecture, security contracts, and verified protocol facts. When code
and spec disagree, the spec wins; fix the spec first, in the same commit as any
behavior change. The behavioral reference is
[d-kuro/kirocc](https://github.com/d-kuro/kirocc) v0.11.1, used as a test
oracle, never as the architectural base.

## 1. Scope

`kiro-trust` is a local proxy that lets Claude Code talk to the Kiro runtime
through AWS IAM Identity Center credentials held by the Kiro CLI. It is the only
process that ever holds the Kiro bearer token. Claude Code sees a loopback
Anthropic Messages API protected by a separate local token.

Two assets drive every decision: the AWS/Kiro credential, and the content
Claude Code sends (source code, prompts, tool output). Protecting them ranks
above observability, convenience, and dynamic behavior.

v0.1 delivers one workflow:

```text
Kiro CLI login (IAM Identity Center)  →  ~/.local/share/kiro-cli/data.sqlite3
Claude Code  →  http://127.0.0.1:3456 + local token  →  kiro-trust
kiro-trust   →  read credentials (read-only)  →  refresh via AWS OIDC
             →  POST https://runtime.<region>.kiro.dev/  (EventStream)
             →  Anthropic SSE back to Claude Code
```

In scope for v0.1:

- `POST /v1/messages`, streaming and non-streaming
- `POST /v1/messages/count_tokens` (local estimate)
- `GET /v1/models` (static catalog)
- `GET /health`
- tool use, extended thinking, images in the current message, tool-level
  prompt caching, `stop_sequences`, `max_tokens`
- IAM Identity Center credentials with automatic OIDC refresh
- static Claude model catalog
- mandatory local token
- `kiro-trust audit`

Out of scope for v0.1, each a deliberate decision rather than an omission:

- social login, Kiro API keys (`ksk_…`)
- GPT models on Kiro
- proxy-side Tool Search, Advisor, truncation notice injection, retry of
  thinking-only responses
- dynamic model discovery, `models sync`
- web UI, remote listener, multi-user, account pooling
- telemetry, OpenTelemetry, crash reporting, update checks
- plugin system, arbitrary upstream URLs, generic OpenAI gateway
- config file, log file rotation, CORS
- Homebrew tap, background service installation
- enterprise CA or HTTP proxy support

Section 13 lists the backlog with the reason each item was deferred.

## 2. Decisions

| Decision | Choice | Rejected alternative and why |
| --- | --- | --- |
| Language | Rust, edition 2024, toolchain pinned to 1.98.1 | Go port of kirocc: memory safety and secret zeroization are cheaper in Rust; the point is a smaller trust boundary, not a rewrite |
| Workspace | five crates plus `xtask` (section 3) | two crates: module visibility cannot prove that `reqwest` lives in one crate; seven crates: bookkeeping without a security gain |
| kirocc usage | oracle: fixtures and transcribed regression tests | line-by-line port: inherits advisor, tool search, OTel hooks, and attribution on every file |
| EventStream framing | own decoder, about 150 lines over `crc32fast`, fuzzed | `aws-smithy-eventstream` 0.61.2: 28 transitive crates including `http` 0.2 and 1.x and `time` for a frame parser; excessive surface for the gain |
| HTTP server | `axum` with default features off (`http1`, `json`, `tokio`) | raw `hyper`: hand-written request parsing is its own risk |
| TLS roots | `webpki-roots` compiled in | native roots: a system CA store or `SSL_CERT_FILE` could insert a middlebox silently |
| Unknown model | 400 `invalid_request_error` | kirocc's silent fallback to Sonnet sends content to a model the user did not pick |
| `count_tokens` | deterministic local estimate | tiktoken: a tokenizer dependency plus data files for an approximation either way |
| Local token transport | `ANTHROPIC_AUTH_TOKEN` (Bearer) or `ANTHROPIC_API_KEY` (`x-api-key`), both accepted | Bearer only: Claude Code picks the header from whichever variable is set |
| Distribution | GitHub Releases with attestations and SBOM, plus owner-dispatched crates.io publish | GitHub only: the owner wants `cargo install kiro-trust` |
| Agent guidance | tracked `CLAUDE.md` holding the rules directly | `AGENTS.md` plus import: the owner asked for one file here |

## 3. Architecture

Dependency direction is one way and enforced by Cargo:

```text
kiro-trust (bin)
  ├── kiro-trust-kiro      → kiro-trust-net, kiro-trust-protocol
  ├── kiro-trust-auth      → kiro-trust-net
  ├── kiro-trust-net       (the only crate that depends on reqwest)
  └── kiro-trust-protocol  (serde only; no tokio, no reqwest, no SQLite)
xtask                      (dev tool, publish = false)
crates/kiro-trust-tests    (publish = false; fixture, security, live tests)
fuzz/                      (cargo-fuzz package, excluded from the workspace)
```

`cargo tree -p kiro-trust-protocol` must show no `reqwest`, `rusqlite`, or
`tokio`. CI asserts it.

### 3.1 kiro-trust-protocol

Pure data and pure functions. Everything here is testable from a fixture file.

- Anthropic request and response types: `Request`, `Message`, content blocks
  (`text`, `image`, `tool_use`, `tool_result`, `thinking`,
  `redacted_thinking`), `Tool`, `ThinkingConfig`, `OutputConfig`, `Usage`,
  streaming event types (`message_start`, `content_block_start`,
  `content_block_delta`, `content_block_stop`, `message_delta`,
  `message_stop`, `ping`, `error`).
- Kiro types: `Payload`, `ConversationState`, `UserInputMessage`,
  `UserInputMessageContext`, `EnvState`, `ToolEntry`, `ToolSpecification`,
  `ToolResult`, `Image`, `CachePoint`, `HistoryEntry`,
  `AdditionalModelRequestFields`, and the decoded `Event` enum.
- `catalog`: the static model table (section 5.2).
- `translate::request`: `Request` plus `BuildOptions` → `Payload` plus a
  `ToolNameMap`.
- `translate::response`: a state machine that consumes `Event` values and
  yields Anthropic streaming events. Non-streaming responses are the same
  events folded into one `Message`.
- `eventstream`: byte decoder producing `Frame { headers, payload }` and the
  `Event` parser on top of it.
- `sse`: serializes streaming events to `event:`/`data:` lines.
- `estimate`: the `count_tokens` heuristic.

Body types implement neither `Display` nor a `Debug` that prints content.
`Debug` on a request prints counts and lengths only.

### 3.2 kiro-trust-net

The single outbound policy. Public surface:

```rust
pub enum Destination {
    Oidc { sso_region: Region },
    Runtime { region: RuntimeRegion },
}
pub struct Region(String);          // validated pattern, section 6.2
pub struct RuntimeRegion(Region);   // pattern plus allowlist
pub struct Client { /* reqwest::Client with the fixed policy */ }
impl Client {
    pub fn new(policy: Policy) -> Result<Self, Error>;
    pub async fn post_json(&self, dest: Destination, path: &str,
        headers: HeaderMap, body: Bytes) -> Result<Response, Error>;
}
```

`Destination` is the only way to name a host. The request path is validated
too: it must start with `/` and carry no userinfo, query, fragment, or
backslash, and the built URL is parsed and checked to name exactly the
destination host before it is sent. There is no `Url` in the public
API. `Policy::production()` is the only constructor the binary uses. A
`test-endpoints` cargo feature adds `Policy::loopback_plain_http(port)` for
this crate's own tests; the binary never enables it and CI proves that.

The client is built with redirects disabled, `no_proxy()`, `rustls` with
`webpki-roots`, HTTPS only, connect timeout 10 s, response header timeout 30 s.
The streaming body wrapper enforces an idle-read deadline of 180 s and a
per-frame size cap. Error bodies are read to at most 64 KiB.

### 3.3 kiro-trust-auth

- `locate()`: default database path per OS (section 7.1) or an override.
- `open_read_only(path)`: `rusqlite` with `SQLITE_OPEN_READ_ONLY |
  SQLITE_OPEN_NO_MUTEX`, `PRAGMA query_only = ON`, and an authorizer that
  allows `SQLITE_SELECT`, `SQLITE_READ` on `auth_kv`, `state`, and
  `sqlite_master`, and `SQLITE_PRAGMA` for `query_only` only. Any other
  action or table returns `SQLITE_DENY`. No SQL function is used; JSON
  values are parsed in Rust.
- `read_identity_center(conn)`: reads the keys in section 7.2 and returns
  `Credentials { access_token: SecretString, refresh_token: SecretString,
  client_id: String, client_secret: SecretString, expires_at: SystemTime,
  sso_region: Region, runtime_region: RuntimeRegion }`. A social token or a
  missing device registration is an error naming the unsupported case.
- `TokenSource`: caches `Credentials` in memory, refreshes when fewer than
  five minutes remain, coalesces concurrent refreshes with a single in-flight
  future, re-reads the database at the start of every refresh cycle, and
  exposes `with_token(|&str| ...)` and `invalidate()`. Nothing is written to
  the database, ever.
- `refresh(net, creds)`: `POST https://oidc.<sso_region>.amazonaws.com/token`
  with `{"grantType":"refresh_token","clientId","clientSecret","refreshToken"}`
  as JSON; reads `accessToken`, `refreshToken` (optional, falls back to the
  old one), `expiresIn` seconds. A non-200 or an empty `accessToken` is an
  error. The response body is never logged.

`Debug` for `Credentials` prints `sso_region`, `runtime_region`, and
`expires_at` only.

### 3.4 kiro-trust-kiro

- `KiroRequest`: builds `POST https://runtime.<region>.kiro.dev/` with the
  headers in section 7.4 and the serialized `Payload`.
- `Upstream` trait: `async fn generate(&self, token, payload, region) ->
  Result<EventStreamBody, UpstreamError>`. The production implementation uses
  `kiro-trust-net`; tests inject a scripted implementation.
- Retry: up to three attempts. 429 and 5xx retry with exponential backoff
  (1 s, 2 s) plus jitter. A 200 whose `Content-Type` is not
  `application/vnd.amazon.eventstream` is decoded as an AWS exception
  envelope; `ThrottlingException` and `InternalServerException` retry, others
  fail. A 403 calls `TokenSource::invalidate()` and retries once with a fresh
  token. Connection errors before any byte is sent retry; errors after the
  stream started do not.
- `UpstreamError { status, exception_type, message (≤ 1 KiB) }` maps to the
  Anthropic error envelope in the server.

### 3.5 kiro-trust (binary)

`clap` subcommands: `serve`, `audit`, `env`. Modules: `config` (flags, env,
validation), `server` (axum routes, middleware, limits), `token` (local token
file), `audit`, `env`. The binary owns the `tracing` subscriber.

### 3.6 xtask

`cargo xtask scrub <capture-dir> <fixture-dir>` (section 8.3),
`cargo xtask check-versions`, `cargo xtask fixtures-verify` which re-runs the
leak scan, and `cargo xtask make-db <path>` which builds the synthetic
placeholder database for the audit gate (section 8.7). Depends on
`kiro-trust-protocol` and `rusqlite` only.

## 4. Command surface

### 4.1 `kiro-trust serve`

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--listen <addr>` | `KIRO_TRUST_LISTEN` | `127.0.0.1:3456` | loopback socket address; a non-loopback IP is a config error |
| `--kiro-db <path>` | `KIRO_TRUST_DB` | per-OS default | Kiro CLI database |
| `--runtime-region <r>` | `KIRO_TRUST_RUNTIME_REGION` | from profile ARN | must pass the allowlist |
| `--token-file <path>` | `KIRO_TRUST_TOKEN_FILE` | per-OS runtime dir | where the generated local token is written |
| (none) | `KIRO_TRUST_TOKEN` | generated | explicit local token; when set, no file is written |
| `--log-level <l>` | `KIRO_TRUST_LOG` | `info` | `error`, `warn`, `info`, `debug` |
| `--share-content` | `KIRO_TRUST_SHARE_CONTENT` | off | sends `x-amzn-codewhisperer-optout: false` (section 7.4); shown in audit |
| `--capture-dir <path>` | — | — | only with the `capture` feature (section 8.3) |

Precedence: flag, then env, then default. Startup order: parse and validate
config, open the database read-only and read credentials (fail fast with a
clear message), write the token file, bind, print one line with the listener
and token file path, serve. On SIGINT or SIGTERM: stop accepting, drain for up
to 10 s, delete the token file, exit 0.

### 4.2 `kiro-trust audit [--json]`

Prints the effective security configuration (section 6.6) and exits 0. Exits 1
when a guarantee does not hold: a dev feature is compiled in, the listener is
not loopback, or the database could not be opened read-only. `audit` never
starts a listener and never performs a network request.

### 4.3 `kiro-trust env [--shell sh|fish]`

Prints the exports Claude Code needs, reading the token file:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:3456
export ANTHROPIC_AUTH_TOKEN=<local token>
```

Usage: `eval "$(kiro-trust env)"`. Exits 1 if no token file exists.

### 4.4 Exit codes

`0` success, `1` runtime failure, `2` usage or configuration error.

## 5. Protocol translation

Every rule below has a fixture or a transcribed kirocc test behind it. Where a
rule says "transcribe from kirocc", the plan task reads the named file and
records the rule here before writing code.

### 5.1 Endpoints

| Route | Auth | Behavior |
| --- | --- | --- |
| `GET /health` | none | `{"status":"ok"}` |
| `GET /v1/models` | local token | static catalog, section 5.2 |
| `POST /v1/messages` | local token | translate, call Kiro, stream or fold |
| `POST /v1/messages/count_tokens` | local token | `{"input_tokens": n}` from section 5.7 |

Any other path returns 404 with the Anthropic error envelope. Methods other
than those listed return 405.

### 5.2 Model catalog

Static, shipped in `kiro-trust-protocol::catalog`, copied from kirocc's Claude
rows with attribution in `NOTICE`.

| Anthropic id | Kiro SKU | 1M SKU | Context | Effort enum |
| --- | --- | --- | --- | --- |
| `claude-opus-5` | `claude-opus-5` | same | 1M | low, medium, high, xhigh, max |
| `claude-opus-4-8` | `claude-opus-4.8` | same | 1M | low, medium, high, xhigh, max |
| `claude-opus-4-7` | `claude-opus-4.7` | same | 1M | low, medium, high, xhigh, max |
| `claude-opus-4-6` | `claude-opus-4.6` | same | 1M | low, medium, high, max |
| `claude-sonnet-5` | `claude-sonnet-5` | same | 1M | low, medium, high, xhigh, max |
| `claude-sonnet-4-6` | `claude-sonnet-4.6` | `claude-sonnet-4.6-1m` | 200k / 1M | low, medium, high, max |
| `claude-sonnet-4.5` | `claude-sonnet-4.5` | `claude-sonnet-4.5-1m` | 200k / 1M | none (effort omitted) |
| `claude-opus-4.5` | `claude-opus-4.5` | — | 200k | none (effort omitted) |
| `claude-haiku-4.5` | `claude-haiku-4.5` | — | 200k | none (effort omitted) |

Transcribed from kirocc v0.11.1 `internal/models/effort.go` on 2026-09-08.

Resolution: strip a trailing `-YYYYMMDD` date, canonicalize a trailing `[1m]`
or `[1M]` to `[1m]`, accept a dashed or dotted minor version
(`claude-sonnet-4-5` and `claude-sonnet-4.5` are the same row), then exact
match. `[1m]` or an `anthropic-beta` header
containing `context-1m` selects the 1M SKU when one exists; on an always-1M
model the suffix is only an alias. Neither enables thinking. An id that does
not resolve returns 400 `invalid_request_error` with the message
`model <id> is not in the kiro-trust catalog`.

`GET /v1/models` returns the shape Claude Code's gateway discovery accepts,
transcribed from kirocc `internal/server/handlers.go`:
`{"object":"list","data":[{"id","object":"model","created","owned_by":"kiro","display_name"}]}`,
listing every catalog row plus a `[1m]` entry with " (1M context)" appended
for rows with a separate 1M SKU.

### 5.3 Request translation

Input: the Anthropic `Request`, the resolved Kiro SKU, the profile ARN, a
conversation id (UUID v4 per request), and the effort level. Output: `Payload`.

1. System prompt: `system` as a string or text blocks joins into one string.
   The `<env>` block, when present, yields `envState.operatingSystem` and
   `envState.currentWorkingDirectory` on the current message only (transcribe
   from kirocc `internal/reqconv/env_state.go`).
2. Tools: `tool_search_tool_*` definitions are dropped and `defer_loading`
   is ignored. Remaining tools become `toolSpecification` entries after
   schema sanitization (transcribe from `schema_sanitize.go`) and name mapping
   (transcribe from `tool_name_map.go`). A tool with `cache_control` gets a
   `cachePoint` entry after it (transcribe from `cache_points.go`). The keys
   of `properties` are parameter names and are never treated as schema
   keywords; only their values are sanitized. Each combinator branch is
   sanitized once.
3. Messages: consecutive same-role messages merge; the last message is the
   current message, everything before is history. A trailing assistant
   message pushes everything to history and synthesizes a `Continue` user
   message (transcribe from `message_normalizer.go`, `history.go`).
4. The system prompt is placed as a history entry pair (transcribe from
   `content_text.go`, `placeSystemPrompt`).
5. Current message: text content, `modelId`, `origin: KIRO_CLI`, tool
   results reordered to the preceding assistant turn's `tool_use` order with
   `status` success or error and content blocks, and images
   (transcribe from `tool_results.go`, `images.go`).
6. Thinking and `redacted_thinking` blocks in history are dropped; only text
   and `tool_use` blocks reach `assistantResponseMessage`. (kirocc replays
   redacted blobs for GPT models only, out of scope.)
7. `profileArn` is set from the credential.
8. Thinking: when `thinking.type` is `enabled` or `adaptive`, or
   `output_config.effort` is set, `additionalModelRequestFields.output_config.effort`
   is the requested effort clamped to the model's enum, defaulting to
   `medium`. `thinking.type: disabled` or absent omits the field.
   `budget_tokens` is ignored.

Fixed values: `chatTriggerType: MANUAL`, `agentTaskType: vibe`.

### 5.4 Response translation

The decoder yields `Event` values (section 7.5). The response state machine
tracks the current block (`thinking`, `text`, `tool_use`, or none) and emits:

- `message_start` with `id: msg_<24 hex>`, the Anthropic model id, empty
  content, and zero usage; real usage arrives in `message_delta`.
- `assistantResponseEvent.content` appends to a text block verbatim. Frames
  are incremental; there is no overlap removal (kirocc #116).
  `<thinking>` tags inside text open and close a thinking block (transcribe
  from `thinking_tags.go`).
- `reasoningContentEvent.text` appends to a thinking block; `signature`
  becomes a `signature_delta`; `redactedContent` becomes a
  `redacted_thinking` block.
- A `signature` on a reasoning event becomes a `signature_delta` on the
  open thinking block.
- `toolUseEvent` frames accumulate `input` fragments per `toolUseId` until
  `stop`; the block emits `content_block_start` with the mapped-back name and
  `input_json_delta` chunks (transcribe from `kiroproto/tooluse.go`); the
  tool block is closed immediately after its single `input_json_delta`.
- `metadataEvent.tokenUsage` sets `input_tokens = uncachedInputTokens +
  cacheReadInputTokens`, `output_tokens`, `cache_read_input_tokens`,
  `cache_creation_input_tokens = cacheWriteInputTokens`. `meteringEvent`
  fills gaps when `metadataEvent` is absent.
- `stop_sequences` are matched across delta boundaries; on a match the text
  is cut, `stop_reason: stop_sequence` and `stop_sequence` are set, and the
  upstream body is dropped. `max_tokens` is enforced on output tokens with
  `stop_reason: max_tokens`.
- `stop_reason` is `tool_use` when at least one tool block closed, else
  `end_turn`.
- An `exception` frame or `invalidStateEvent` before any visible output
  becomes an HTTP error (section 5.6); after output started it becomes an
  SSE `error` event followed by `message_stop`.
- End of stream: close the open block, `message_delta` with `stop_reason` and
  usage, `message_stop`.
- Idle keep-alive: an SSE comment line `: keep-alive` every 15 s without an
  event.

Non-streaming: the same events folded into one `Message` JSON body.

### 5.5 Request limits

| Limit | Value |
| --- | --- |
| Request body | 32 MiB |
| Header read timeout | 10 s |
| Concurrent requests | 32; excess gets 429 `rate_limit_error` |
| JSON nesting | serde_json default recursion limit (128) |
| Tools per request | 512 |
| Messages per request | 4096 |
| Upstream frame | 4 MiB |
| Upstream error body | 64 KiB |
| Tool input accumulation | 16 MiB per tool call |

### 5.6 Errors

Every failure uses `{"type":"error","error":{"type":"<t>","message":"<m>"}}`.

| Condition | Status | `error.type` |
| --- | --- | --- |
| missing or wrong local token | 401 | `authentication_error` |
| body too large, bad JSON, unknown model, invalid field | 400 | `invalid_request_error` |
| unknown route | 404 | `not_found_error` |
| Kiro credential unusable (no database, refresh failed) | 401 | `authentication_error` |
| upstream 429 or `ThrottlingException` after retries | 429 | `rate_limit_error` |
| upstream 5xx, malformed stream, idle timeout | 502 | `api_error` |
| upstream 400-class other than 403/429 | 502 | `api_error` |
| local concurrency cap | 429 | `rate_limit_error` |

The message carries the upstream exception type and message capped at 1 KiB.
It never carries request content, the local token, or a Kiro token.

### 5.7 `count_tokens`

`input_tokens = ceil(utf8_bytes(system + message text + tool_use inputs +
tool_result text + tool definitions JSON) / 4) + 3 × messages`. Deterministic,
offline, documented as approximate.

## 6. Security contracts

Each line here maps to a test in `tests/security/` (section 8.4).

### 6.1 Credential database

- Opened read-only with the flags in 3.3; an attempt to open writable is a
  compile-time impossibility because no such constructor exists, and the
  authorizer test proves an `UPDATE` fails at runtime.
- Only `auth_kv` and `state` are read, only by the exact keys in 7.2.
  `history`, `conversations`, `conversations_v2`, and every telemetry key are
  never touched.
- Refreshed tokens live in memory only. Nothing writes to the database, no
  copy of the file is made, no table is created.
- Secrets are `secrecy::SecretString` (zeroized on drop). They are never
  formatted, serialized, or included in an error message.

### 6.2 Outbound network

- Hosts: `oidc.<sso_region>.amazonaws.com` and `runtime.<region>.kiro.dev`.
  No other host can be constructed in a production build.
- Region pattern: `^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`, at most 32 bytes. Runtime
  regions must also be one of `us-east-1`, `eu-central-1`, `us-gov-east-1`,
  `us-gov-west-1`. New runtime regions ship in a release.
- HTTPS only. Redirects are errors: a 3xx from either host fails the request
  without following. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`
  are ignored. TLS roots are `webpki-roots` compiled in; `SSL_CERT_FILE` and
  the system store are ignored.
- Timeouts per 3.2. The Kiro bearer token appears in exactly one place: the
  `Authorization` header of a runtime request.

### 6.3 Local listener

- Bind addresses must be loopback (`127.0.0.0/8` or `::1`). Anything else
  is a configuration error with no override in v0.1.
- The local token is 32 bytes from the OS CSPRNG, base64url without padding,
  written atomically (temp file plus rename) to the token file with directory
  mode 0700 and file mode 0600, and deleted on shutdown. On Windows the file
  inherits the user profile ACL.
- Every route except `/health` requires the token in `Authorization: Bearer`
  or `x-api-key`, compared in constant time. A failure returns 401 with no
  `WWW-Authenticate` challenge.
- No CORS headers. `OPTIONS` returns 405.

### 6.4 Logging

- `tracing` to stderr only. Allowed fields: `request_id`, `method`, `path`,
  `model`, `kiro_model`, `stream`, `status`, `duration_ms`, `retry_count`,
  `input_bytes`, `output_bytes`, `input_tokens`, `output_tokens`,
  `runtime_region`, `sso_region`, `frames`, `event_counts`, `error_type`.
- Never logged: any header value, request or response body, prompt, tool
  name, tool argument, tool result, thinking text, conversation id, profile
  ARN, account id, token, client secret, refresh token, database path
  beyond its basename.
- There is no body-logging flag. Payload capture exists only behind the
  `capture` cargo feature and is compiled out of release builds.

### 6.5 Telemetry

None. No exporter, no crash reporter, no update check, no remote
configuration. The only outbound traffic is the two hosts in 6.2.

### 6.6 Audit output

`kiro-trust audit` prints, in this order:

```text
kiro-trust <version> (<commit>)

Credential source
  Kiro CLI SQLite      ~/.local/share/kiro-cli/data.sqlite3
  mode                 read-only, authorizer enforced

Authentication
  type                 AWS IAM Identity Center
  SSO region           ap-southeast-1
  token expires        2026-09-08T14:27:34Z (refresh on demand)

Runtime
  region               us-east-1 (from profile)

Allowed outbound
  oidc.ap-southeast-1.amazonaws.com
  runtime.us-east-1.kiro.dev

TLS roots              webpki-roots (compiled in)
HTTP proxy             disabled (environment ignored)
Redirects              rejected

Local listener         127.0.0.1:3456
Local authentication   required (token file 0600)

Telemetry              none
Kiro content sharing   opted out (x-amzn-codewhisperer-optout: true)
Request body logging   disabled (no flag exists)
Dynamic model discovery disabled
Automatic updates      disabled

Build features         none
```

The profile ARN and account id are never printed. `--json` emits the same
data as one object. When `Build features` lists `capture` or
`test-endpoints`, audit exits 1.

## 7. Verified facts

Measured on 2026-09-08 against a Kiro CLI 2.21.x database and kirocc v0.11.1
source. Anything not listed here is unverified until a fixture proves it.

### 7.1 Database location

| OS | Path |
| --- | --- |
| Linux | `~/.local/share/kiro-cli/data.sqlite3` |
| macOS | `~/Library/Application Support/kiro-cli/data.sqlite3` |
| Windows | `%LOCALAPPDATA%\kiro-cli\data.sqlite3` |

The Linux and macOS paths are confirmed by the owner's installs; the Windows
path is from kirocc `internal/config/config.go`.

### 7.2 Schema and keys

Tables: `auth_kv(key TEXT PRIMARY KEY, value TEXT)`, `state(key TEXT PRIMARY
KEY, value BLOB)`, plus `conversations`, `conversations_v2`, `history`,
`migrations`, `pinned_bin_versions`, `extracted_kas_versions`, which
kiro-trust never reads.

Identity Center keys, first match wins:

- token: `kirocli:odic:token`, `kirocli:oidc:token`
- device registration: `kirocli:odic:device-registration`,
  `kirocli:oidc:device-registration`
- `state.auth.idc.region`: JSON string, the SSO region
- `state.api.codewhisperer.profile`: JSON `{"arn":"arn:aws:codewhisperer:<region>:<account>:profile/<id>","profile_name":"..."}` or a bare ARN string

Social keys (`kirocli:social:*`) are checked only to produce the unsupported
error. The legacy `codewhisperer:*` keys are not read in v0.1.

Token JSON fields accept camelCase or snake_case: `accessToken`/`access_token`,
`refreshToken`/`refresh_token`, `expiresAt`/`expires_at`, `region`. The
measured database stores `expires_at` as an RFC 3339 string with fractional
seconds (`2026-09-08T14:27:34.854803Z`) and `region: "ap-southeast-1"`.
Expiry parsing accepts RFC 3339, integer or float Unix seconds, and their
string forms. Device registration fields: `clientId`/`client_id`,
`clientSecret`/`client_secret`.

Runtime region resolution order: token `region` only if it passes the
allowlist, else the ARN region, else `state.auth.idc.region` if allowlisted,
else a configuration error. The measured database resolves to SSO region
`ap-southeast-1` and runtime region `us-east-1` from the ARN.

### 7.3 OIDC refresh

`POST https://oidc.<sso_region>.amazonaws.com/token`, `Content-Type:
application/json`, body `{"grantType":"refresh_token","clientId","clientSecret","refreshToken"}`.
Response `{"accessToken","refreshToken"?,"expiresIn"}` with `expiresIn` in
seconds. Verified in kirocc `internal/auth/refresh.go`; the live tier confirms
it on this laptop.

### 7.4 Runtime request

`POST https://runtime.<region>.kiro.dev/` with headers:

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer <access token>` |
| `Content-Type` | `application/x-amz-json-1.0` |
| `Accept` | `*/*` |
| `X-Amz-Target` | `AmazonCodeWhispererStreamingService.GenerateAssistantResponse` |
| `User-Agent` | `aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.17593 os/macos lang/rust/1.92.0 md/appVersion-2.10.0 app/AmazonQ-For-CLI` |
| `x-amz-user-agent` | `aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.17593 os/macos lang/rust/1.92.0 m/F app/AmazonQ-For-CLI` |
| `x-amzn-codewhisperer-optout` | `true` (default; `false` only with `--share-content`, shown in audit) |
| `amz-sdk-invocation-id` | UUID v4 per request |
| `amz-sdk-request` | `attempt=<n>; max=3` |

The user-agent strings are pinned to the kiro-cli 2.10.0 capture kirocc
emulates; a capture from kiro-cli 2.21 may update them in one place. The
opt-out header defaults to `true` unlike kirocc; the live tier verifies the
runtime accepts it, and the fallback is a documented flag.

### 7.5 EventStream frames and events

Frame: 12-byte prelude (`total_length` u32 BE, `headers_length` u32 BE,
prelude CRC32 u32 BE over the first 8 bytes), headers, payload, message CRC32
u32 BE over everything before it. CRC is IEEE (`crc32fast`). Header encoding:
name length u8, name, type u8, value; type 7 is a string with u16 BE length.
Headers used: `:message-type` (`event` or `exception`), `:event-type`,
`:content-type`, `:exception-type`. `total_length` below 16 or above 4 MiB is
a decode error; a truncated prelude with zero bytes read is a clean end.
A header block over 128 KiB is a decode error.

Events and payload fields:

| `:event-type` | Payload | Handling |
| --- | --- | --- |
| `assistantResponseEvent` | `{content}` | text delta |
| `reasoningContentEvent` | `{text, signature, redactedContent}` | thinking delta |
| `toolUseEvent` | `{toolUseId, name, input, stop}` fragments | accumulate per id |
| `metadataEvent` | `{tokenUsage:{uncachedInputTokens, outputTokens, totalTokens, cacheReadInputTokens, cacheWriteInputTokens}}` | usage |
| `meteringEvent` | `{usage, inputTokens, outputTokens}` | usage fallback |
| `invalidStateEvent` | `{reason, message}` | error |
| `messageMetadataEvent` | `{conversationId, utteranceId}` | ignored |
| `contextUsageEvent` | `{contextUsagePercentage}` | ignored |
| `followupPromptEvent`, `citationEvent`, `codeEvent`, `codeReferenceEvent`, `supplementaryWebLinksEvent`, `intentsEvent`, `interactionComponentsEvent`, `dryRunSucceedEvent`, `initial-response` | any | ignored |
| unknown | any | counted, ignored, never logged |

`:message-type: exception` carries `{message}` and `:exception-type`.

Text frames are incremental, not cumulative (kirocc v0.11.1, issue #116).
Concatenate verbatim.

### 7.6 Kiro payload

```json
{
  "conversationState": {
    "conversationId": "<uuid>",
    "chatTriggerType": "MANUAL",
    "agentTaskType": "vibe",
    "currentMessage": {
      "userInputMessage": {
        "content": "...",
        "modelId": "claude-sonnet-4.6",
        "origin": "KIRO_CLI",
        "userInputMessageContext": {
          "envState": {"operatingSystem": "...", "currentWorkingDirectory": "..."},
          "tools": [{"toolSpecification": {"name", "description", "inputSchema": {"json": {}}}}, {"cachePoint": {"type": "default"}}],
          "toolResults": [{"toolUseId", "status", "content": [{"text": "..."}]}]
        },
        "images": [{"format": "png", "source": {"bytes": "<base64>"}}]
      }
    },
    "history": [{"userInputMessage": {...}}, {"assistantResponseMessage": {"content", "toolUses": [...]}}]
  },
  "profileArn": "arn:aws:codewhisperer:...",
  "additionalModelRequestFields": {"output_config": {"effort": "medium"}}
}
```

Field names verified against kirocc `internal/kiroproto/types.go`. The exact
`history` entry shapes, `cachePoint` value, and image encoding are transcribed
in Phase 1 from `types.go` and confirmed by the first live capture.

### 7.7 Runtime regions

Kiro serves `us-east-1`, `eu-central-1`, `us-gov-east-1`, `us-gov-west-1`
(kirocc README, 2026-09). A credential whose SSO region is elsewhere (the
owner's is `ap-southeast-1`) still refreshes against its own OIDC region and
targets the ARN region for the runtime.

## 8. Testing

### 8.1 Tiers

| Tier | Command | Needs |
| --- | --- | --- |
| unit | `cargo test --workspace` | nothing |
| fixture | same, data in `tests/fixtures/`, tests in `crates/kiro-trust-tests` | nothing |
| security | same, `crates/kiro-trust-tests` | nothing |
| fuzz | `cargo +nightly fuzz run <target> -- -max_total_time=300` | nightly toolchain, weekly CI |
| live | `KIRO_TRUST_LIVE=1 cargo test --workspace -- --ignored --test-threads=1` | the Kiro database on this laptop |
| smoke | Claude Code through the proxy, by hand | same, recorded in release notes |

The offline suite must pass on `ubuntu-latest`, `macos-latest`, and
`windows-latest`.

### 8.2 Fixture format

`tests/fixtures/<case>/` holds:

- `meta.json`: `{"source": "capture kiro-cli 2.21.1 2026-09-10" | "kirocc v0.11.1 <test name>", "features": ["text","stream","tool_use",...]}`
- `request.json`: the Anthropic request as the client sent it
- `expected-payload.json`: the Kiro payload kiro-trust must produce
- `upstream.eventstream`: raw bytes from the runtime, when the case has a
  response; a transcribed case may instead give `upstream.events.json`, a
  readable list of `{"event_type": .., "payload": ..}` or
  `{"exception_type": .., "payload": ..}` objects, one per frame, that the
  harness re-encodes to the same bytes
- `expected-sse.txt` or `expected-message.json`: the Anthropic output

Fixture tests compare the produced payload with `expected-payload.json` as
JSON values (key order independent, `conversationId` masked) and the produced
SSE with `expected-sse.txt` byte for byte after masking `msg_` ids.

`expected-payload.json`, `expected-sse.txt`, and `expected-message.json` are
generated, never hand-written: run the fixture test with `UPDATE_FIXTURES=1`
to (re)write them from the current `request.json` and upstream frames, then
review the diff by hand before committing. A generated file that contradicts
this spec is a product bug to fix, not an expectation to edit.

Priority cases, in order: plain text; streaming text; frame boundaries inside
multi-byte characters and repeated bytes; tool call; tool result; extended
thinking; multiple content blocks; `max_tokens`; `stop_sequences`;
cancellation mid-stream; throttling; token expiry; 403 then refresh;
malformed frame; truncated stream; 200 with JSON exception.

### 8.3 Capture and scrub

The `capture` cargo feature adds `--capture-dir`. For every request it writes
`<n>-request.json`, `<n>-payload.json`, `<n>-upstream.eventstream`,
`<n>-upstream-headers.json`, and `<n>-response.sse` with mode 0600. The
feature is off by default, absent from release builds, and reported by
`audit` with exit 1.

`cargo xtask scrub <capture-dir> <fixture-dir>` replaces the profile ARN and
account id with `arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE`,
conversation and utterance ids with fixed strings, the home directory with
`/home/user`, hostnames with `host`, and removes upstream headers other than
`content-type`. `scripts/check-fixtures.sh` fails when any file under
`tests/fixtures/` contains a 12-digit account id, `arn:aws:` outside the
fixture ARN, the owner's home path, an `aoa`-prefixed or `eyJ`-prefixed
token-shaped string, or a `kiro.dev` hostname with a real region other than
the fixture's.

Fixtures are public. Record only marker prompts (`kiro-trust fixture probe:
...`) so no real source code enters the repository.

### 8.4 Security tests

One test per line, in `crates/kiro-trust-tests/tests/security.rs` (net and
auth cases enable the `test-endpoints` feature from that crate only):

- `open_writable_is_impossible`: `UPDATE auth_kv` through the connection
  fails with an authorizer denial
- `only_auth_tables_are_readable`: `SELECT` from `history` fails
- `authorization_never_logged`, `refresh_token_never_logged`,
  `client_secret_never_logged`, `prompt_never_logged`,
  `tool_args_never_logged`: run the full fixture suite with a capturing
  subscriber at `debug` and assert none of the markers appear
- `oidc_redirect_rejected`, `runtime_redirect_rejected`: a 302 from a
  loopback test server is an error and no second request is made
- `invalid_region_rejected`: `us-east-1/`, `evil.com`, `US-EAST-1`,
  `ap-southeast-1` (not allowlisted for runtime) all fail before any hostname
  exists
- `proxy_env_ignored`: with `HTTPS_PROXY` set to a listening socket, no
  connection reaches it
- `non_loopback_bind_fails`: `0.0.0.0:3456` and `192.168.1.10:3456` are
  config errors
- `missing_token_401`, `wrong_token_401`, `health_needs_no_token`
- `no_url_in_net_api`: compile-time, `Destination` is the only host input
- `binary_has_no_dev_features`: `cargo tree -e features -p kiro-trust`
  contains neither `capture` nor `test-endpoints` (script in CI). The check
  and every release build select `-p kiro-trust` alone, because a workspace
  wide build would unify the test crate's features into the binary
- `protocol_crate_is_pure`: `cargo tree -p kiro-trust-protocol` contains no
  `reqwest`, `rusqlite`, `tokio`

### 8.5 Fuzz targets

`fuzz/fuzz_targets/`: `frame_decode` (bytes → frames), `event_parse`
(frame → `Event`), `sse_translate` (event sequence → SSE, asserting no panic
and block state invariants), `anthropic_request` (bytes → `Request`),
`tool_input_accumulate` (fragment sequences). Seeds come from the fixtures. A
weekly CI job runs each for five minutes; a crash file is committed as a
regression fixture.

### 8.6 Live tier

`crates/kiro-trust-tests/tests/live.rs`, ignored by default. Each test reads
the real database, sends
a marker prompt with `max_tokens: 64`, and asserts on structure, never on
model wording: streaming text arrives; a tool call to a `kiro_trust_probe`
tool produces `tool_use`; a thinking request produces a `thinking` block;
forcing expiry triggers a refresh; an invalid token yields 403 then a
successful retry. Live tests print token counts and durations only.

### 8.7 CI gates

`ci.yml` on push to `master`, pull requests, and weekly:

1. `cargo fmt --all --check`
2. `cargo clippy --locked --workspace --all-targets -- -D warnings`
3. `cargo test --locked --workspace` on Linux, macOS, Windows
4. `cargo deny check advisories bans licenses sources`
5. `./scripts/check-packages.sh` (versions, package contents)
6. `./scripts/check-fixtures.sh`
7. `./scripts/check-features.sh` (8.4, last two lines)
8. audit gate: `cargo build --release --locked -p kiro-trust` then
   `target/release/kiro-trust audit --json --kiro-db tests/fixtures/db/idc.sqlite3`
   compared with `tests/fixtures/db/idc-audit.json`

`tests/fixtures/db/idc.sqlite3` is a synthetic database built by
`cargo xtask make-db` with placeholder values; it is not a scrubbed copy.

## 9. Distribution and release

### 9.1 Artifacts

cargo-dist 0.32.0, `dist-workspace.toml`:

- targets: `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`
- `checksum = "sha256"`, `github-attestations = true`,
  `cargo-cyclonedx = true`, `cargo-auditable = true` (dist installs the two
  cargo tools in its generated workflow; `release-preflight.yml` proves it
  before the first tag)
- installers: `shell`, `powershell`
- `profile.dist`: `lto = "thin"`, `codegen-units = 1`, `strip = true`,
  `panic = "abort"`

Every workflow pins actions by commit SHA with the tag in a comment.
`release.yml` is generated by `dist` then hand-edited to `contents: read`
with `write` only on the `host` job; `allow-dirty = ["ci"]` keeps the edits.

Verification a user can run: `gh attestation verify <archive> --owner
dannyota`, and `sha256sum -c`. The SBOM is a `.cdx.json` per package on the
release.

No Homebrew tap and no quarantine removal.

### 9.2 Procedure

`docs/releasing.md` holds the maintainer steps: bump every version field,
add the CHANGELOG entry, push `master`, require CI green on the exact commit,
dispatch `release-preflight.yml` (`cargo publish --workspace --dry-run
--locked`), `git tag -s vX.Y.Z`, push the tag, confirm the asset list
including attestations and SBOMs. The release ends there.

### 9.3 crates.io

Never automatic. `publish-crates.yml` is dispatched by the owner with the
tag: a `verify` job checks out `refs/tags/<tag>`, requires every version
field to equal the tag, requires a complete GitHub Release, checks that all
five crates exist on crates.io with owner `dannyota`, and repeats the dry run;
a `publish` job then waits for the `crates-io` environment approval and
publishes through Trusted Publishing. Approval is per version and never
carries forward. Publish order is `kiro-trust-protocol`, `kiro-trust-net`,
`kiro-trust-auth`, `kiro-trust-kiro`, `kiro-trust`, submitted as one workspace
publish. The first publication of each crate needs a separate owner decision
because Trusted Publishing cannot create a crate.

## 10. Versioning

Semantic versioning over the CLI surface, the flag and environment variable
names, the audit text and JSON keys, the fixture format, and the security
contracts in section 6. Weakening any contract in section 6 is a major
change. Adding a catalog row or a runtime region is a minor change. All
crates share one version.

v0.1.0 is tagged when every line below holds on this laptop:

```text
Claude Code works through it        (manual smoke, recorded)
IAM Identity Center works            (live tier)
Kiro token refresh works             (live tier, forced expiry)
tool calls work                      (fixture + live)
thinking works                       (fixture + live)
streaming works                      (fixture + live)
no prompt logging                    (security tests)
no telemetry                         (cargo tree, audit)
no dynamic model lookup              (no code path)
no arbitrary network destination     (Destination type, security tests)
no unauthenticated local proxy       (security tests)
no writable Kiro credential access   (authorizer test)
no automatic update                  (no code path)
```

## 11. Credentials in this repository

The development laptop holds a real Identity Center credential at the default
Linux path. Live tests may use it without asking. Nothing under the
repository may contain a token, client secret, refresh token, profile ARN,
account id, or the owner's home path; `scripts/check-fixtures.sh` enforces it
for fixtures and the pre-push review enforces it for everything else. No
`.env` file exists in this project because the proxy reads nothing from the
environment except its own `KIRO_TRUST_*` variables.

## 12. Risks

- **Kiro protocol drift.** The runtime is undocumented. Mitigation: fixtures
  from real captures, a pinned user-agent, and the live tier before every
  release.
- **Header emulation.** kiro-trust presents itself as kiro-cli. If Kiro
  rejects the pinned user-agent, the fix is a capture and a release.
- **Opt-out header.** `x-amzn-codewhisperer-optout: true` is untested against
  the runtime until the live tier runs; the fallback flag is specified.
- **Region allowlist staleness.** A new Kiro region needs a release; the
  error message names the allowlist and this file.
- **Claude Code feature growth.** Tool Search and other beta features are
  dropped in v0.1; a client that depends on them gets all tools active and a
  larger prompt, not a failure.
- **Custom frame decoder.** Mitigated by fuzzing, bounded allocation, CRC
  validation, and transcribed kirocc regression cases.

## 13. Backlog

Deferred with reasons; each becomes a spec change before code.

| Item | Why deferred |
| --- | --- |
| retry of thinking-only responses (kirocc gate writer) | needs buffered SSE; measure how often Kiro returns no visible text first |
| truncation notice injection | modifies the next prompt; decide after live use |
| proxy-side Tool Search (`tool_search_tool_regex`, `bm25`) | server-tool emulation; all tools active is correct, only larger |
| binary differential run against kirocc | kirocc cannot target a fake upstream without patching |
| `kiro-trust exec -- claude` | keeps the token out of the shell; small, after `env` proves the flow |
| enterprise CA flag | explicit `--extra-ca <pem>` shown in audit |
| `models sync` command | user-initiated catalog fetch from `management.<region>.kiro.dev` |
| social login, Kiro API key | separate refresh host and header; out of the v0.1 trust boundary |
| GPT models | different reasoning schema |
| cosign step in addition to attestations | attestations already Sigstore-backed |
| Homebrew tap | must not strip quarantine; needs notarization |

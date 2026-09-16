# kiro-trust — design

Status: v0.3.0 release candidate, 2026-09-10. This document is the source of truth for
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
- HTTP proxy support

Section 13 lists the backlog with the reason each item was deferred.

Four of those out-of-scope items are closed decisions rather than schedule
slips, and 0.2.0 removed them from the backlog so that table stops implying
they are coming: proxy-side Tool Search, `models sync`, social login, and Kiro
API keys. `AGENTS.md` forbids porting each. Social login and API keys would add
a second credential type, widening the trust boundary this project exists to
keep narrow; `models sync` and Tool Search would add an outbound host and
server-tool emulation, and section 6.5 bans model discovery outright, flag or
no flag.

0.2.0 moved three former backlog items into scope: `kiro-trust exec`
(section 4.5), an additive enterprise CA flag (section 4.1), and a header read
timeout with an idle connection cap (section 6.3). It also added image format
validation and per-image and per-request limits. The proxy forwards images in
the current message. It drops history images until the live test in section
8.6 proves that runtime behavior.

The 0.3.0 candidate adds offline model inspection through `models list` and
`models show` (section 4.2.1), `kiro-trust doctor` (section 4.6), bounded
retry handling, and the process-local usage summary at `GET /v1/usage`.
Doctor checks local configuration by default. `doctor --network` also sends an
explicit loopback health probe. The refresh-token chain keeps refreshed
credentials in memory and does not update the Kiro CLI database. Manual model
discovery and history-image forwarding stay deferred behind their separate
evidence gates.

The next release classifies the monthly allowance marker (section 5.6). A live
capture on 2026-09-16 recorded the marker and passed its evidence gate.

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
| Agent guidance | tracked `AGENTS.md` holds the rules; `CLAUDE.md` contains `@AGENTS.md` | duplicated rules in both files can drift |

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

Most of the kirocc-derived code in this workspace lives here (NOTICE), so
`cargo package` for this crate would otherwise ship without attribution:
`cargo package` only ever includes files inside a crate's own directory, so
the repository-root `NOTICE` cannot be referenced from outside it. This
crate, `kiro-trust-kiro`, and `kiro-trust` each carry a byte-identical copy
of the root `NOTICE` at their own crate root; each crate's `lib.rs` has a
test (`notice_sync::crate_notice_matches_workspace_notice`) that fails if
its copy drifts from the original. `kiro-trust-net` and `kiro-trust-auth`
hold no kirocc-derived code and carry no copy.

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
    pub fn new(policy: Policy) -> Result<Self, NetError>;
    pub async fn post(&self, dest: &Destination, path: &str,
        headers: HeaderMap, body: Vec<u8>) -> Result<Response, NetError>;
}
pub async fn probe_loopback_health(addr: SocketAddr) -> Result<(), NetError>;
```

`Destination` is the only way to name a remote host. The request path is validated
too: it must start with `/` and carry no userinfo, query, fragment, or
backslash, and the built URL is parsed and checked to name exactly the
destination host before it is sent. There is no `Url` in the public
API. `Policy::production()` is the only constructor the binary uses. A
`test-endpoints` cargo feature adds `Policy::loopback_plain_http(port)` for
this crate's own tests; the binary never enables it and CI proves that.

`probe_loopback_health` is the one public exception: it accepts a loopback
`SocketAddr` for a fixed unauthenticated HTTP/1 `GET /health`. It rejects
non-loopback addresses inside the net crate and returns only the fixed
`NetError::HealthProbe` error on failure. The caller cannot change its URL,
path, method, or headers. Section 4.6 defines its single two-second total
deadline, with connection bounded within that deadline, and its body bound.

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
  future, and exposes `with_token(|&str| ...)` and `invalidate()`. Nothing is
  written to the database, ever.

  A refresh cycle re-reads the database first; a read that fails ends the
  cycle with that error, forced or not, since every rule below is a decision
  about what the database currently holds. It then follows three rules. They
  exist because a refresh token that has been exchanged must never be sent
  again (RFC 6749 section 6; RFC 9700 section 4.14 has the authorization
  server read a replayed token as a stolen-token signal). Section 12,
  "Refresh token rotation", carries the reasoning.

  1. **The database wins when it is strictly newer.** If the credential just
     read is valid, and its `expires_at` is later than the cached one's (or
     nothing is cached), serve it and drop the cached one. The Kiro CLI owns
     the credential, and one it refreshed after our last read supersedes
     anything held here. "Later than", never "different from": once this
     process has refreshed, the cached credential's expiry differs from the
     database row as a matter of course, so "different" would hand the cycle
     back to a credential whose refresh token we already exchanged.
  2. **Chain from the newest token held.** Otherwise refresh, sending the
     refresh token of whichever credential has the later `expires_at`: the
     cached one once this process has refreshed at least once, the database's
     otherwise. The result is cached, so the next cycle chains from the token
     this one received rather than re-sending the database's.
  3. **Never re-send an exchanged token.** When a refresh fails, re-read the
     database and retry once only if its `expires_at` differs from the value
     the database held at the top of this cycle, which means the Kiro CLI has
     written a new credential since. Otherwise the error names the failure and
     says to log in to Kiro CLI again. Retrying with the older copy would be
     exactly the replay rule 3 exists to prevent.

     A refresh can also fail after the OIDC endpoint accepted it: a 200 whose
     body does not parse, an empty `accessToken`, an `expiresIn` outside the
     guard, a body that fails to read, or the 30-second cap firing after the
     response status arrived. The token is spent in every one of those, so
     such a seed is never chained from again in this process; a later cycle
     that finds only a burned seed fails with the same error and makes no
     network call.

     A seed that was successfully exchanged is burned too, and for the same
     reason: it is the one seed we know for certain is spent. The decision is
     made once, when the refresh ends by any route, and turns on a single
     question: had a 200 already arrived? Burned: a successful exchange, and
     any failure after a 200. Left usable: a failure before any response
     status arrived, and any non-200 status. It is deliberately not a mark
     placed before the request and lifted afterwards on the way out; a lift
     that some exit path skips is how a seed gets burned that was never
     spent.

     Those two lifted classes are a deliberate trade, not a proof. A request
     that reached Identity Center and was answered slowly, or a 502 from an
     intermediary in front of a token service that had already committed the
     rotation, spends the token while looking exactly like a transient
     failure. kiro-trust treats both as not-exchanged anyway, because the
     alternative strands a long-lived local proxy on an ordinary network blip:
     every later cycle would refuse to refresh a token that is still good,
     until a restart or a Kiro CLI write. The replay risk in those two narrow
     cases is accepted; section 12 records it.

     A refresh that is cancelled mid-flight, which happens whenever the Claude
     Code client disconnects while a request is in the handler, is not a
     separate case: it ends the refresh like any other route, so the same
     question decides it. Cancelled after a 200 burns; cancelled before one
     does not. Deciding at the end rather than at the start is what makes
     cancellation ordinary instead of a path someone has to remember.

     `refresh()` must therefore report which side of the response status it
     failed on, and must make that fact observable to the cancellation path as
     well as the error path; collapsing both into one network-error variant is
     what makes the safe classification impossible. The soundness of the burn
     signal rests on the network policy in section 6.2: a non-AWS 200 cannot
     reach it while the compiled roots pin `oidc.<region>.amazonaws.com`.
     `--extra-ca` widens that, as it widens everything else it touches.

  These rules compare `expires_at`, a non-secret field the CLI rewrites
  together with the refresh token, so deciding which credential is newer never
  compares secret values and adds no `expose_secret()` site (section 6.5). An
  `expiresAt` the parser cannot use reads as `UNIX_EPOCH` (section 7.2), which
  is a sentinel and not a time: it is never "later than" anything and never
  proves two reads are the same credential, so a cycle holding one refreshes
  rather than serving it, and rule 3 treats it as no change. It still burns:
  because the sentinel cannot identify one credential, rule 3 records it as a
  single flag rather than as a value in the burned set, which stops an
  unparsable row from being replayed without limit. That flag is one way and
  process-wide, so once any unparsable seed is spent, a later and genuinely
  different unparsable row is refused too, and a restart is the only recovery.
  Nothing about the sentinel could tell the two apart, so there is no signal
  that could safely clear it. The same collision has a cost on the parsable
  side: a Kiro CLI credential written with the same `expires_at` as a row this
  process already exchanged is refused until a restart, rather than merely
  missing a retry. The digest in section 13 is what would remove both. Distinguishing
  two CLI writes that share an expiry would need a digest of the stored row;
  section 13 carries that as backlog, since `expires_at` covers every write
  the CLI actually performs.

  `invalidate()` (used after an upstream 403, which retries at most once)
  marks the next cycle as forced rather than dropping the cached credential,
  so the chain's newest refresh token survives a 403 and rule 3 still holds.
  Dropping the cache instead, as versions before 0.3.0 did, would send the
  database's already-exchanged token on the next cycle. A forced cycle skips
  the cached-credential shortcut, re-reads the database, and serves what it
  finds only under rule 1's strict comparison; otherwise it refreshes under
  rule 2, with one bound.

  **A forced cycle never refreshes a credential this process itself minted by
  refresh, while that credential is still valid.** It serves that credential
  again and lets the 403 reach the client; once it is past its expiry the
  bound no longer applies and the cycle refreshes under rule 2. A token issued minutes ago and still rejected is not what the
  runtime is objecting to, and another exchange from the same grant would be
  rejected the same way; without this bound a runtime returning 403 for a
  reason unrelated to the credential (entitlement, profile, a middlebox) costs
  one refresh per request, and every refresh may rotate the owner's token.
  That is the harm section 12 exists to bound, so the honest 403 is worth
  more than the retry.

  The 403 handler calls `invalidate()` only when an attempt remains, so a
  request that gives up leaves no forced cycle behind. The flag is
  process-wide and the swap is first-come, so a concurrent request may consume
  a cycle another request forced; that costs one wasted round trip and never
  puts an exchanged token on the wire.
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
- `Upstream` trait: `async fn generate(&self, payload: &Payload) ->
  Result<UpstreamStream, UpstreamError>`. Its additive
  `generate_with_progress(&self, payload: &Payload, progress:
  &AttemptProgress)` default records the returned stream or error count once.
  The production implementation uses `kiro-trust-net`; tests inject a
  scripted implementation.
- Retry: up to three completed `net.post()` calls. Retryable 429 and 5xx
  responses honor a valid `Retry-After` of at most 60 seconds; invalid or past
  values use exponential backoff (1 s, 2 s) plus jitter. A longer valid delay
  stops retries and becomes a normalized local `Retry-After` response header.
  An all-digit delay too large for `u64` stops retries without a local header.
  The exact `INSUFFICIENT_MODEL_CAPACITY` marker on a retryable 429 or 5xx, or in a
  decoded non-eventstream exception, is a transient model-capacity error. A
  200 whose `Content-Type` is not
  `application/vnd.amazon.eventstream` is decoded as an AWS exception
  envelope; retryable exception types and every decoded model-capacity
  exception retry, others fail. A 403 calls `TokenSource::invalidate()` when
  an attempt remains, and
  retries once with whatever that forced cycle yields: a newer credential the
  Kiro CLI wrote, a freshly refreshed one, or, when this process minted the
  rejected credential itself, the same one again (section 3.3). A second 403,
  or a 403 on the last attempt, fails with an authentication error. Connection errors before any
  byte is sent retry; errors after the stream started do not. A completed post
  includes a response or transport error, and increments only after the post
  future returns. Credential and header failures before a post count zero.
- `UpstreamError { attempts, retry_after, status, exception_type, message
  (≤ 1 KiB) }` maps to the Anthropic error envelope in the server. Header
  values never enter its display or debug output. `AttemptProgress` is a
  cloneable saturating count of completed posts. The additive
  `Upstream::generate_with_progress` default records a returned stream or
  error count. `KiroClient` records each completed post immediately, before
  response inspection or an await, so cancellation during a retry sleep or a
  pending later post retains the completed count without double counting.

### 3.5 kiro-trust (binary)

`clap` subcommands: `serve`, `audit`, `env`, `exec`, `models`, and `doctor`. Modules:
`config` (flags, env, validation), `server` (axum routes, middleware, limits),
`token` (local token file), `serve` (the `serve` command: credential read,
bind, shutdown), `logging` (the `tracing` subscriber and its `EnvFilter`),
`audit`, `env`, `exec`, and `models_cmd`. The binary owns the `tracing`
subscriber; it is installed once, from `logging::init`, before `serve::run`
starts. `models list` and `models show` return before logging initialization,
credential access, listener access, or network-client construction.

`doctor` reports fixed, non-secret local diagnostics. It opens the credential
database read-only but never constructs `TokenSource` or refreshes a
credential. It is offline unless `--network` is present.

### 3.6 xtask

`cargo xtask scrub <capture-dir> <fixture-dir> --source "<text>"` (section
8.3), `cargo xtask fixtures-verify` which shells out to
`scripts/check-fixtures.sh` rather than reimplementing the leak scan (a
second implementation is exactly the kind of thing that drifts from the
first), and `cargo xtask make-db <path>` which builds the synthetic
placeholder database for the audit gate (section 8.7). There is no
`check-versions`: an earlier version was `println!("versions ok")`
regardless of whether versions matched, a gate that failed open with nothing
in CI to catch it, and `scripts/check-packages.sh` already does the real
check. Depends on `kiro-trust-protocol`, `serde_json`, and `rusqlite` only.

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
| `--extra-ca <pem>` | `KIRO_TRUST_EXTRA_CA` | — | additional PEM trust anchor, added to the compiled roots, never replacing them (section 6.2); shown in audit |
| `--capture-dir <path>` | — | — | only with the `capture` feature (section 8.3) |

Precedence: flag, then env, then default. Startup order: parse and validate
config, read and parse `--extra-ca` when given (a missing, unreadable,
malformed, or empty PEM file is a configuration error, exit 2, before anything
is written or bound), open the database read-only and read credentials (fail
fast with a clear message), write the token file, bind, print two lines to
stderr (the listener address and token file path, then a reminder to run
`kiro-trust env`), serve. A failure at any step before the token file is
written leaves no token file behind; a failure after binding removes it. On
SIGINT or SIGTERM: delete the token file and stop accepting immediately (no
new client can read a valid token during the drain that follows), drain
existing connections for up to 10 s, exit 0.

### 4.2 `kiro-trust audit [--json]`

Prints the effective security configuration (section 6.6) and exits 0. Exits 1
when the listener address cannot be parsed or is not loopback, an invalid
`--runtime-region` is given, the database cannot be confirmed read-only, the
credential cannot be read, or a dev feature is compiled in. `audit` never
starts a listener and never performs a network request.

### 4.2.1 `kiro-trust models list [--json]` and `kiro-trust models show <model> [--json]`

Both commands inspect the compiled catalog only. They do not open the Kiro
database, read a token, contact a listener, or create a network client.

Text `list` output has `ID`, `KIRO MODEL`, `CONTEXT`, `INPUTS`, and `EFFORT`
columns. JSON is `{"object":"model_catalog","models":[ModelInfo...]}` in
catalog order. Text `show` prints each `ModelInfo` field in a stable order.
JSON is the selected `ModelInfo`. An unknown id exits 1 and writes exactly
`kiro-trust: unknown model; run 'kiro-trust models list' for supported models`
to stderr. The error never includes caller input.

### 4.3 `kiro-trust env [--shell sh|fish]`

Prints the exports Claude Code needs, reading the token file. Before
printing, the token is checked against the shape `token::generate` produces
(43 characters of base64url without padding, spec 6.3); anything else is
rejected without being echoed, not even a prefix.

```sh
export ANTHROPIC_BASE_URL='http://127.0.0.1:3456'
export ANTHROPIC_AUTH_TOKEN='<local token>'
```

`--shell fish` prints the fish form instead:

```fish
set -gx ANTHROPIC_BASE_URL 'http://127.0.0.1:3456'
set -gx ANTHROPIC_AUTH_TOKEN '<local token>'
```

Both forms single-quote both values. Usage: `eval "$(kiro-trust env)"`.
Exits 1 when the token file does not exist, cannot be read, or does not
contain a well-formed token.

### 4.4 `kiro-trust exec -- <cmd> [args...]`

Runs a command with `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` set and
nothing else in the environment changed. It reads and validates the token file
exactly as `env` does (section 4.3), rejecting a malformed token without
echoing it, then hands the token to the child. Compared with
`eval "$(kiro-trust env)"`, the token never enters a shell, a shell history, or
the environment of any process but the child.

On Unix it replaces itself with the child through `exec`, so no wrapper process
survives; elsewhere it spawns the child and forwards its exit code. Exits 1 when
the token file does not exist, cannot be read, or does not hold a well-formed
token, and 2 when no command is given or when `--listen` is not a loopback
address. `--listen` is validated, not merely interpolated: it decides where the
child sends the token and every prompt, so a non-loopback value would hand both
to a remote host. It is rejected before the token file is read.

`exec` never constructs a shell invocation, never passes a command string to be
word-split, and never lets an argument be reinterpreted, so nothing the caller
writes can be expanded or injected. It does not override `execvp(3)`'s POSIX
behavior of running an executable file with no shebang through `/bin/sh`; that
child gets the token as intended, since the caller named the program.

`CommandExt::exec` resets `SIGPIPE` to `SIG_DFL` before `execvp` and does not
restore it when `execvp` fails, so this command reinstates `SIG_IGN` on that
failure path. Without it, writing the error message to a stderr with no reader
killed the process with `SIGPIPE` (exit 141), outside the codes section 4.5
allows. This is the one direct `libc` use in the binary, declared
`[target.'cfg(unix)'.dependencies]`; `libc` is already compiled in through
`directories`.

This is the sixth and last permitted `expose_secret()` site (section 6.1). The
justification matches `env`'s: passing the token to the child is the command's
entire purpose, and there is no implementation without one. The token reaches
the child's environment only, never a log, stderr, or an error path.

### 4.5 Exit codes

`0` success, `1` runtime failure, `2` usage or configuration error.

### 4.6 `kiro-trust doctor`

`kiro-trust doctor [--json] [--network] [--listen <loopback-address>]
[--kiro-db <path>] [--runtime-region <region>] [--token-file <path>]
[--extra-ca <pem>]` reports five checks in this order: configuration,
database, credential expiry, local token, and listener. It reports only the
fixed snake-case check names, statuses, and details below. It never emits a
database value, ARN, account id, token, header value, raw network body, or
upstream error text.

The configuration check parses the loopback address and runtime-region
override, resolves the database and token-file paths, and validates an optional
extra CA. The database check opens the database only through
`KiroDb::open_read_only`, verifies `query_only`, and parses the credential.
The expiry check is `valid` when more than five minutes remain,
`refresh_required` when a positive interval of five minutes or less remains,
and `expired` when the expiry is reached or unavailable. Doctor does not
refresh, so an expiry warning makes no promise about refresh success.

The local-token check uses `symlink_metadata` only. It never reads token-file
contents. A present `KIRO_TRUST_TOKEN` reports `explicit_token_configured`
without inspecting its value. On Unix a token file must be regular and have no
group or other mode bits. Windows reports `acl_not_verified` for a regular
file. Missing token files are warnings because `serve` creates them.

Without `--network`, listener is `skipped` with `network_disabled`. With it,
the only request is the fixed, unauthenticated HTTP/1 `GET /health` to the
configured loopback socket. The private net client disables proxies and
redirects, applies one two-second total probe deadline, reads at most 256
bytes, and accepts only status 200, `application/json`, and exactly
`{"status":"ok"}`. It rejects a non-loopback address again inside the net
crate. No token, caller-provided method, path, host, or header enters the
probe.

`DoctorReport` serializes as `version`, `paths`, and `checks`. `paths` has
optional `database`, `token_file`, and `extra_ca` fields whose paths use the
same home abbreviation as audit. `checks` has fixed `name`, `status`, and
`detail` enums. Text output renders the paths first, then `NAME STATUS DETAIL`.
The command exits 1 when any check is an error; warning-only and skipped-only
reports exit 0.

| Check condition | Status | Detail |
| --- | --- | --- |
| Configuration parses and optional CA loads | ok | valid |
| Invalid listener, region, path resolution, or CA | error | invalid_configuration |
| Database opens read-only and credential parses | ok | read_only |
| Database missing or unreadable | error | database_unavailable |
| Read-only assertion or credential parsing fails | error | credential_invalid |
| More than five minutes until expiry | ok | valid |
| Positive expiry interval at most five minutes | warning | refresh_required |
| Expiry reached or unavailable | warning | expired |
| Credential unavailable | skipped | credential_unavailable |
| Explicit local token variable is present | ok | explicit_token_configured |
| Private Unix token file | ok | private_file |
| Token file missing | warning | token_file_missing |
| Token metadata unreadable | error | token_metadata_unreadable |
| Symlink, nonregular, or unsafe Unix token file | error | unsafe_token_file |
| Regular Windows token file | warning | acl_not_verified |
| Offline listener check | skipped | network_disabled |
| Network probe succeeds | ok | healthy |
| Network probe fails | error | health_probe_failed |
| Invalid configuration prevents a dependent check | skipped | invalid_configuration |

## 5. Protocol translation

Every rule below has a fixture or a transcribed kirocc test behind it. Where a
rule says "transcribe from kirocc", the plan task reads the named file and
records the rule here before writing code.

### 5.1 Endpoints

| Route | Auth | Behavior |
| --- | --- | --- |
| `GET /health` | none | `{"status":"ok"}` |
| `GET /v1/models` | local token | static catalog, section 5.2 |
| `GET /v1/usage` | local token | process-local usage summary, section 6.7 |
| `POST /v1/messages` | local token | translate, call Kiro, stream or fold |
| `POST /v1/messages/count_tokens` | local token | `{"input_tokens": n}` from section 5.7 |

Any other path returns 404 with the Anthropic error envelope. Methods other
than those listed return 405.

`POST /v1/messages` requires `max_tokens`; an absent or zero value is 400
`invalid_request_error` (section 5.6), matching the real Anthropic Messages
API. The requirement lives in the `/v1/messages` handler, not in
`anthropic::Request` or its shared parser: `count_tokens` parses the same
`Request` type and legitimately omits the field (section 5.7).

### 5.2 Model catalog

Static, shipped in `kiro-trust-protocol::catalog`, copied from kirocc's Claude
rows with attribution in `NOTICE`. The catalog exposes owned metadata through
`ModelInfo`, keyed by the private `ModelKey`. A key covers one valid catalog
row and context tier and cannot be constructed from caller text. `models()`
returns every routable row and tier in catalog order. `model(&str)` resolves a
catalog id to its metadata. `supports_kiro_model(&str)` recognizes Kiro SKUs
only. `Resolved` carries the same `ModelKey` as the metadata row.

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
match. `[1m]` or an `anthropic-beta` header containing `context-1m` selects
the 1M SKU when one exists. On an always-1M model the suffix is only an alias.
On a separate-1M-SKU row, an explicit `[1m]` enables thinking. The
`context-1m` beta header and raw 1M SKU select context without independently
enabling thinking. An id that does not resolve returns 400
`invalid_request_error` with the message `model <id> is not in the kiro-trust
catalog`.

Each metadata entry has its routed Anthropic id, display name, Kiro SKU,
concrete aliases, date-suffix acceptance, context window, effort levels,
proxy input types, and history-image forwarding state. Metadata aliases stay
within one `ModelKey`, include canonical ids, Kiro SKUs, and dashed or dotted
forms, and never contain a placeholder date. `proxy_input_types` is always
`text,image`: it states what the proxy accepts and forwards, not remote model
vision support. `history_images_forwarded` is `false` until the live evidence
test in section 8.6 passes. `ModelKey` is never serialized.

`GET /v1/models` returns the shape Claude Code's gateway discovery accepts,
transcribed from kirocc `internal/server/handlers.go`:
`{"object":"list","data":[{"id","object":"model","created","owned_by":"kiro","display_name"}]}`,
listing every catalog row plus a `[1m]` entry with " (1M context)" appended
for rows with a separate 1M SKU.

### 5.3 Request translation

Input: the Anthropic `Request`, the resolved Kiro SKU, the profile ARN, a
conversation id (derived per step 8), and the effort level. Output: `Payload`.

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
   (transcribe from `tool_results.go`, `images.go`). Images nested inside a
   tool result are promoted to the message and noted in that result's `stdout`,
   because a Kiro tool result cannot carry an image: `ToolResultContent` is
   text or JSON only, on both the Kiro CLI and kirocc. `userInputMessage.images`
   is the only image channel for a turn.

   `format` comes from the `media_type` suffix and must be one of `gif`,
   `jpeg`, `png`, `webp`: the closed `ImageFormat` enum in the Kiro CLI's
   generated SDK (`amzn-codewhisperer-streaming-client`, `_image_format.rs`).
   There is no `jpg` variant. Anything else is 400 `invalid_request_error`
   naming the received media type and the four accepted ones. `image/jpg` is
   rejected rather than corrected to `jpeg`: guessing a caller's intent is how
   an invalid enum value reaches the runtime, which returns an opaque error
   instead. Anthropic's four documented media types map onto the enum exactly,
   so a well-formed request never sees this. Base64 that does not decode is
   also 400. Per-image and per-request size limits are in section 5.5.

   An image whose `source.type` is not `base64` (a URL) is skipped, not
   rejected, matching both the Kiro CLI and kirocc. Nothing about a skipped or
   rejected image is logged: section 6.4's allowlist has no field for one.
6. Thinking and `redacted_thinking` blocks in history are dropped; only text
   and `tool_use` blocks reach `assistantResponseMessage`. (kirocc replays
   redacted blobs for GPT models only, out of scope.) Images in a history user
   entry are sent, with the same validation, limits, and tool-result promotion
   as the current message. `history` is a list of the same `UserInputMessage`
   type the current message uses, so the field exists there
   (`_chat_message.rs`, `_user_input_message.rs`), and the Kiro CLI's shipped
   `chat` path populates it (`into_history_entry` sets `images`, and the SDK
   conversion calls `.set_images()` on the history builder). Its newer `agent`
   path hardcodes `images: None` there, as kirocc does, and neither explains
   why, so the SDK proves the field exists but not that the runtime honors it.
   `history_image_is_accepted` (section 8.6) is that evidence and gates this
   rule: without a passing live test, history images are dropped and this
   paragraph says so instead. Without them, an image pasted in one turn is
   invisible from the next turn on, because Claude Code resends the whole
   conversation each time.
7. `profileArn` is set from the credential.
8. `conversationId`: UUID v5 of the `X-Claude-Code-Session-Id` header under a
   per-process random namespace, or a random UUID v4 when the header is
   absent, so Kiro sees a stable conversation per Claude Code session
   without receiving the raw session id.
9. Thinking: when `thinking.type` is `enabled` or `adaptive`, or
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
  `stop_reason: max_tokens`. The translator's accumulated text, thinking,
  tool-call input, and redacted content share one output-token counter that
  is additionally bounded by a fixed absolute ceiling (section 5.5),
  independent of the client's `max_tokens`: defense in depth so accumulation
  stays bounded even if the field is ever made optional again.
- `stop_reason` is `tool_use` when at least one tool block closed, else
  `end_turn`.
- An `exception` frame or `invalidStateEvent` before any visible output
  becomes an HTTP error (section 5.6); after output started it becomes an
  SSE `error` event and the stream ends there, with no `message_stop`
  after it.
- An `invalidStateEvent` with reason `CONTENT_LENGTH_EXCEEDS_THRESHOLD`,
  `INVALID_CONVERSATION_STATE`, or `STALE_CONVERSATION` clears the
  conversation id and retries the request once (kirocc
  `retryableInvalidStateReasons`); any other reason, or a second retryable
  failure, is the HTTP error above. What counts as "output has started",
  which ends retry eligibility, is per path: streaming counts any content
  already buffered as translated events as started, since those bytes are on
  the wire once the handler flushes them, so the retry never happens once
  the first content is buffered. Non-streaming holds everything back until
  the whole response is folded, so a retryable invalid state still retries
  even after earlier content (a `reasoningContentEvent`, say) has been
  translated internally, as long as this is the request's first retry.
- End of stream: close the open block, `message_delta` with `stop_reason` and
  usage, `message_stop`.
- Idle keep-alive: an SSE comment line `: keep-alive` every 15 s without an
  event. Keep-alive comments start after the first event; there is none
  before it.

Non-streaming: the same events folded into one `Message` JSON body.

### 5.5 Request limits

| Limit | Value |
| --- | --- |
| Request body | 32 MiB |
| Concurrent requests | 32; excess gets 429 `rate_limit_error`. An open SSE connection holds its slot for the life of the connection, not just while the upstream call is being primed. |
| JSON nesting | serde_json default recursion limit (128) |
| Tools per request | 512 |
| Messages per request | 4096 |
| Images per request | 10, counting images promoted out of tool results; excess is 400 `invalid_request_error` naming the limit. Transcribed from the Kiro CLI's `MAX_NUMBER_OF_IMAGES_PER_REQUEST`. That CLI drops the extras and warns on its terminal; kiro-trust has no such channel and section 6.4 forbids logging anything about an image, so a silent drop would leave the model answering about an image it never received. A 400 tells the caller. |
| Image size | 10 MB of decoded bytes per image, over which is 400 `invalid_request_error` naming the limit. Transcribed from the Kiro CLI's `MAX_IMAGE_SIZE` and `MAX_IMAGE_SIZE_BYTES`. Measured on decoded length, not the base64 text, because upstream measures file size; validating that requires the base64 to decode at all, which is its own 400 (section 5.3). |
| Upstream frame | 4 MiB |
| Upstream error body | 64 KiB |
| Tool input accumulation | 16 MiB per tool call |
| Response accumulator ceiling | 2,000,000 output tokens (about 8,000,000 accumulated characters across text, thinking, tool-call input, and redacted content combined), independent of the client's `max_tokens` (section 5.4). Far above any legitimate response, so it never changes observable behavior for a real request; it exists only so a future change that makes `max_tokens` optional again cannot reopen unbounded accumulation. |
| Priming deadline | 120 s wall-clock, from the first upstream read until the translator produces its first output (`ResponseTranslator::started`), on both the streaming and non-streaming paths. Generous next to the 10 s connect and 30 s response-header timeouts (section 3.2), and comfortably above a healthy request's time to a first token, including a heavy `max`-effort reasoning load; well under the 180 s per-read idle deadline, so it still meaningfully bounds a stalled connection. Corrects the earlier claim that `Pump::prime` was "bounded by the 180 s read-idle timeout": that timeout resets on every successful read, however small, so an upstream delivering one byte every 179 s never tripped it and could pin a concurrency permit indefinitely. Once output has started this deadline no longer applies for the rest of the response: a long generation is legitimate, and the per-read idle timeout and the SSE keep-alive (above) cover it. Expiry fails the request as an upstream `Transport` error (502 `api_error`, section 5.6) and releases the concurrency permit. |

### 5.6 Errors

Every failure uses `{"type":"error","error":{"type":"<t>","message":"<m>"}}`.

| Condition | Status | `error.type` |
| --- | --- | --- |
| missing or wrong local token | 401 | `authentication_error` |
| bad JSON, unknown model, invalid field (including a missing or zero `max_tokens` on `/v1/messages`, section 5.1) | 400 | `invalid_request_error` |
| request body over 32 MiB | 413 | `request_too_large` |
| unknown route | 404 | `not_found_error` |
| method not allowed | 405 | `invalid_request_error` |
| Kiro credential unusable (no database, refresh failed) | 401 | `authentication_error` |
| upstream throttling or model capacity after retries | 429 | `rate_limit_error` |
| monthly request allowance exhausted (never retried) | 429 with `x-should-retry: false`, no `Retry-After` | `rate_limit_error` |
| upstream 5xx, malformed stream, idle timeout (including the priming deadline, section 5.5) | 502 | `api_error` |
| upstream 400-class other than 403/429, without the allowance marker | 502 | `api_error` |
| local concurrency cap | 429 with `Retry-After: 1` | `rate_limit_error` |

The message carries the upstream exception type and message capped at 1 KiB.
It never carries request content, the local token, or a Kiro token. ARNs and
12-digit account ids are scrubbed from the message before it reaches a
client or a log: any `arn:` run up to the next whitespace, quote, or end of
string becomes `arn:***`, and any bare 12-digit run becomes `***`.

For retryable HTTP errors, parse `Retry-After` as an integer delay or HTTP
date. A valid delay over 60 seconds stops the retry loop and is emitted as the
remaining delay rounded up to whole seconds. The proxy never forwards the raw
upstream value. Invalid, negative, and past values use jitter. The exact
`INSUFFICIENT_MODEL_CAPACITY` marker is transcribed from
`aws/amazon-q-developer-cli` commit
`15cc8f3cd18c4272925ce1c7053268eedff1ea0a`,
`crates/chat-cli/src/api_client/mod.rs`, which checks it before its general
429 classification. The legacy wording fallback and context-overflow branch
are not transcribed.

The exact `MONTHLY_REQUEST_COUNT` marker is transcribed from the same file at
the same commit. That file matches the marker as a byte substring of the error
body, and the generated SDK lists the value as a `reason` on both
`ServiceQuotaExceededException` and `ThrottlingException`. The recorded
fixture `tests/fixtures/errors/monthly-request-count` is the runtime's HTTP 400
response with an exhausted allowance: an AWS JSON 1.0 body whose `__type` is
`ServiceQuotaExceededException`, whose `message` is "You have reached the
limit.", and whose `reason` is `MONTHLY_REQUEST_COUNT`. The response carries no
`x-amzn-errortype` header.

`KiroClient::generate()` classifies a bounded error body that contains the
marker as `AllowanceExhausted` on three paths: a 400-class status other than
403, a 429 or 5xx status, and a 200 whose body is a JSON exception. Precedence
is the capacity marker, then the allowance marker, then the status or
exception type. So a 429 or `ThrottlingException` that carries the allowance
marker is exhaustion, not transient throttling. Unlike the Kiro CLI, which
checks 429 first, the proxy puts the allowance marker ahead of 429 because
retrying cannot succeed before the allowance resets. An exhausted allowance
ends the retry loop at once, ignores any `Retry-After`, and becomes 429
`rate_limit_error` with `x-should-retry: false`. Anthropic SDK clients,
including Claude Code, honor that header and do not retry. The message starts
with `Kiro monthly request allowance exhausted:`. Words such as `quota` or
`limit`, and the exception type alone, never establish exhaustion.

Exception frames inside an event stream keep their existing classification.
The frame decoder keeps only a frame's exception type and `message`, and no
capture shows the allowance marker in a frame.

### 5.7 `count_tokens`

`input_tokens = ceil(utf8_bytes(system + message text + tool_use inputs +
tool_result text + tool definitions JSON) / 4) + 3 × messages +
sum(ceil(decoded_image_bytes / 750))`. Deterministic, offline, documented as
approximate.

The image term is as rough as the rest of the estimate and is there to stop the
endpoint being actively misleading: before 0.2.0 an image contributed nothing,
so a 5 MB paste estimated as zero tokens. `count_tokens` applies no image
validation and no limits from section 5.5, matching how it already tolerates a
request the `/v1/messages` handler would reject.

## 6. Security contracts

Each line here maps to a test in `crates/kiro-trust-tests/tests/security_net.rs`
or `security_logging.rs` (section 8.4).

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
- `expose_secret()` has exactly six call sites in production code:
  `TokenSource::with_token`, the OIDC refresh request builder,
  `server::require_token`, `token::write_temp_file`, `env_cmd::run`, and
  `exec_cmd::run`. The last two exist because printing the token (section 4.3)
  and handing it to a child process (section 4.4) are those commands' entire
  purpose; in both, the token reaches only stdout or the child's environment,
  never a log, stderr, or an error path. A `#[cfg(test)]` function may expose a
  value it constructed itself in order to assert on it, which does not add a
  seventh site.

### 6.2 Outbound network

- Hosts: `oidc.<sso_region>.amazonaws.com` and `runtime.<region>.kiro.dev`.
  No other host can be constructed in a production build.
- Region pattern: `^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`, at most 32 bytes. Runtime
  regions must also be one of `us-east-1`, `eu-central-1`, `us-gov-east-1`,
  `us-gov-west-1`. New runtime regions ship in a release.
- HTTPS only. Redirects are errors: a 3xx from either host fails the request
  without following. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`
  are ignored. TLS roots are `webpki-roots` compiled in; `SSL_CERT_FILE` and
  the system store are ignored. `--extra-ca <pem>` (section 4.1) adds the
  anchors in one PEM file to that compiled set. It is additive only: it cannot
  remove or replace a compiled root, so the flag can let a corporate
  interception proxy through but cannot narrow what is already trusted. A PEM
  that does not parse, or holds no certificate, is a configuration error at
  startup, never a silent fallback to the default roots. `audit` prints the
  path so the deviation is visible.
- Timeouts per 3.2. The Kiro bearer token appears in exactly one place: the
  `Authorization` header of a runtime request.
- `doctor --network` is the sole exception to the HTTPS destination policy. It
  may make one unauthenticated plaintext HTTP/1 `GET /health` request to its
  configured loopback `SocketAddr`. It has no caller-controlled request
  components, disables proxies and redirects, and does not change the outbound
  policy for `serve`, `audit`, model commands, or inference.

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
- The listener is a `GuardedListener` implementing axum's `Listener` trait,
  wrapping `TcpListener`. It caps concurrent connections at `MAX_CONNECTIONS`
  (32) and fails a connection whose first request has not been parsed within
  `HEADER_READ_TIMEOUT` (15 s). Both bounds cover what the `MAX_CONCURRENT`
  semaphore cannot: that semaphore bounds `/v1/messages` handlers, while these
  bound connections that never reach a handler.

  `accept` takes a semaphore permit before accepting, so at the cap the process
  stops accepting rather than accepting and dropping. The trait's `accept`
  cannot return an error, so backpressure has to work by not accepting; that is
  why the permit is acquired ahead of the accept call. Accept errors retry on
  axum's own policy: return immediately on a per-connection error, and log plus
  sleep one second otherwise. `Listener::Io` is a `GuardedIo` wrapper holding
  the stream, the permit, and the deadline; the permit releases when the wrapper
  drops.

  The deadline runs from accept until axum invokes the outer `headers_received`
  middleware for the first parsed request on the connection. While the deadline
  is armed, `GuardedIo::poll_read` races the stream against the deadline and
  returns `io::ErrorKind::TimedOut` when the deadline wins, which ends the
  connection. A silent client and a client trickling header bytes both trip it.
  Writes never disarm it.

  The signal is a parsed request, not a first response write. A first-write
  deadline would kill valid slow requests: `/v1/messages` can wait on a
  credential refresh, on upstream response headers, and on `Pump::prime` for
  well over 15 s after hyper has parsed the request, and the proxy must not
  cancel those. Nothing scans the byte stream for `\r\n\r\n`; hyper owns HTTP
  syntax, and a local scanner could classify an input form differently than
  hyper does.

  The disarm path is a cloneable `HeaderDeadline` holding an atomic armed flag.
  `ConnectionInfo { remote_addr, header_deadline }` implements
  `Connected<IncomingStream<'_, GuardedListener>>` by reading
  `IncomingStream::io()` and `remote_addr()`, so the router is served through
  `into_make_service_with_connect_info::<ConnectionInfo>()`, and the outer
  middleware disarms the deadline before running the inner stack. Axum calls
  that middleware only after hyper has parsed a complete request, which is what
  makes it a sound signal. The bound therefore applies to the first request on
  each HTTP/1 connection; later requests on a kept-alive connection are covered
  by the connection cap alone.

  `ListenerExt::tap_io` cannot express this: it lends `&mut Io` and cannot
  substitute a wrapper type, so the `Listener` impl is hand-written. This
  replaces the manual `hyper_util` accept loop the backlog once proposed.
  `axum::serve` and its graceful shutdown stay in place deliberately: the drain
  ordering, the token-file deletion before the drain, and the deadline task that
  exits 0 (section 4.1) are load-bearing, and rebuilding them to gain a
  header deadline would trade a small exposure for a large one. Serving a
  make-service with connect info is the only change to that call.

### 6.4 Logging

- `tracing` to stderr only. Allowed fields: `request_id`, `method`, `path`,
  `model`, `kiro_model`, `stream`, `status`, `duration_ms`, `retry_count`,
  `attempt`, `input_bytes`, `output_bytes`, `input_tokens`, `output_tokens`,
  `runtime_region`, `sso_region`, `frames`, `event_counts`, `error_type`.
  `attempt` is `kiro-trust-kiro`'s per-call completed-post count.
  `retry_count` is completed posts across the request, including the permitted
  invalid-state replay, minus one and saturated at zero. The usage guard reads
  the same `AttemptProgress` value at completion, failure, and
  cancellation.
  `crates/kiro-trust-tests/tests/security_logging.rs` asserts every `field=`
  name on a captured log line is in this list.
- Never logged: any header value, request or response body, prompt, tool
  name, tool argument, tool result, thinking text, conversation id, profile
  ARN, account id, token, client secret, refresh token, database path
  beyond its basename.
- There is no body-logging flag. Payload capture exists only behind the
  `capture` cargo feature and is compiled out of release builds.
- `--log-level`/`KIRO_TRUST_LOG` accepts exactly `error`, `warn`, `info`,
  `debug` (section 4.1); either source is validated at the CLI boundary, and
  an unrecognized value is a usage error (exit 2), never a silent fallback.
- A validated level only ever raises this project's own crates
  (`kiro_trust`, `kiro_trust_auth`, `kiro_trust_kiro`, `kiro_trust_net`).
  Third-party crates, notably `hyper`, `rustls`, and `reqwest`, stay at
  `warn` at every level the CLI accepts, so they never log request data. The
  filter is built from the parsed level and a fixed target list, never by
  interpolating the raw string into a directive list, so a `,` or `=`
  inside it can never introduce or widen a directive for another target.

### 6.5 Telemetry

None. No exporter, no crash reporter, no update check, no remote
configuration. Remote traffic goes only to the two hosts in section 6.2.
`doctor --network` also permits the explicit unauthenticated loopback health
probe defined in section 4.6.

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
Extra CA               none
HTTP proxy             disabled (environment ignored)
Redirects              rejected

Local listener         127.0.0.1:3456
Local authentication   required (token file 0600)
Connection limits      32 connections, 15s header read timeout

Telemetry              none
Kiro content sharing   opted out (x-amzn-codewhisperer-optout: true)
Request body logging   disabled (no flag exists)
Doctor network         explicit unauthenticated GET /health to configured loopback
Dynamic model discovery disabled
Automatic updates      disabled

Build features         none
```

One PEM file may hold at most `MAX_EXTRA_CA_CERTIFICATES` (16) certificates.
The bound is not tidiness: rustls-webpki spends a global budget of 100
signature checks per verification, and exhausting it is a fatal
`MaximumSignatureChecksExceeded` that halts path building rather than skipping
one anchor, so a large enough bundle stops the runtime host from verifying even
though its genuine compiled root is still present and still first in the store.
Measured against rustls-webpki 0.103.14: 51 anchors verify, 100 fail. An
oversized file is therefore a configuration error at startup, naming the count
and the limit, rather than an opaque TLS failure on every later call.

Validation establishes that each block is a structurally valid X.509
certificate, which is what `RootCertStore::add` checks. It does not check
expiry, key usage, or `basicConstraints`, so an expired certificate or a
`CA:FALSE` leaf is accepted. That is deliberate: the operator names the file,
it only ever adds anchors, and rustls ignores anchor expiry during verification
anyway, so a stricter check would reject files that would in fact work.

`Extra CA` shows the PEM path when `--extra-ca` is set, and the word `none`
otherwise, so an added anchor is never invisible. The path goes through
`abbreviate_home_path`, like the credential path above it, so a home directory
never reaches the output; certificate bytes never appear at all. A problem
string carrying the same path goes through `abbreviate_home_in_message`, which
abbreviates a match followed by a path separator, the end of the string, or any
character that cannot continue a path component. That last case is load-bearing:
`--extra-ca "$HOME"` produces `--extra-ca <path>: Is a directory`, where the
path is followed by `:`, and requiring a separator printed the real home
directory in both the text and `--json` forms. Because the
flag is additive (section 6.2), the `TLS roots` line above it stays true either
way. An unreadable or malformed file adds a sanitized problem and makes audit
exit 1, since a configured anchor that cannot be loaded is a deviation the
operator has to see. `Connection limits` is fixed text derived from
`MAX_CONNECTIONS` and `HEADER_READ_TIMEOUT` (section 6.3).

`Doctor network` is fixed policy text backed by the loopback probe tests in
`security_net.rs`. Its JSON field is `doctor_network`, with the exact value
`explicit unauthenticated GET /health to configured loopback`. The line
describes the permitted request; it does not claim that a listener was
contacted. Audit itself never probes the listener.

On Windows, `Local authentication` reads
`required (token file, user profile ACL)`, matching 6.3: Windows sets no
explicit file mode, so audit does not claim one.

The profile ARN and account id are never printed. `--json` emits the same
data as one object. When `Build features` lists `capture` or
`test-endpoints`, audit exits 1.

### 6.7 Process-local usage summary

`serve` owns an in-memory usage summary that starts empty and disappears when
the process exits. Authenticated `GET /v1/usage` returns the summary without
contacting Kiro and does not count as model usage. The response contains
`object: "usage_summary"`, an RFC 3339 `since` timestamp, flattened request,
token, duration, retry, and error counters, plus nonzero catalog-model rows.
The summary has no file, database, telemetry, reset route, or billing claim.

Token counts retain separate `reported` and `estimated` buckets. Metadata or
metering with a nonzero input or output reports both values. Otherwise the
existing local estimates remain estimated. Cache read and cache write values
always remain reported. The translator replaces an earlier snapshot rather
than adding it. The Anthropic response `usage` shape remains unchanged.

The summary begins after known-model resolution and before the local
concurrency permit. Local authentication and unknown-model rejection stay
outside it. Later local payload or image validation records `invalid_request`.
Identity failures record `authentication`. Upstream `Auth`, `Throttled`,
`ModelCapacity`, `Transport`, `Protocol`, and `Server` or `Client` map to
`authentication`, `transient_throttle`, `model_capacity`, `transport`,
`protocol`, and `upstream_server`. Decoded invalid state maps to
`invalid_state`; decoded capacity and throttle exceptions use the matching
fixed categories, and other decoded exceptions use `upstream_server`.
Upstream `AllowanceExhausted` maps to `allowance_exhausted` (section 5.6).

Each request owns one attempt-progress handle across the ordinary call and
the one permitted invalid-state replay. Completed transport attempts determine
retries as `completed - 1`, including cancellation. The final observed attempt
supplies token values. A streamed request keeps its guard through the initial
SSE batch and completes when it yields the terminal event. A body drop before
a terminal transition records `cancelled`. One lock updates global and bounded
catalog-model counters, preserving the request-count invariant before
saturation. All counters saturate at `u64::MAX`.

Priming reports the latest translator snapshot after every completed pump
chunk and before another upstream await. Cancelling either response mode while
priming therefore retains observed metadata or text. An invalid-state replay
clears the discarded attempt snapshot before it starts the final attempt.

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

Measured on the owner's database on 2026-09-09: every credential row in
`auth_kv` and `state` has SQLite storage class TEXT; the reader accepts TEXT
or UTF-8 BLOB.

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
`windows-latest`. The live command above skips `forced_refresh_succeeds`: that
test needs a second, explicit `KIRO_TRUST_LIVE_REFRESH=1` alongside
`KIRO_TRUST_LIVE=1` (section 8.6), so a plain live run reporting success does
not mean the forced-refresh path ran.

### 8.2 Fixture format

`tests/fixtures/<case>/` holds:

- `meta.json`: `{"source": "capture kiro-cli 2.21.1 2026-09-10" | "kirocc v0.11.1 <test name>", "features": ["text","stream","tool_use",...]}`.
  `source` is the only field the fixture harness checks
  (`crates/kiro-trust-tests/tests/fixtures.rs`); `features` is
  documentation, not read back by any test. Streaming behavior comes from
  `request.json`'s own `stream` field, since that is what a real client
  actually sent; `cargo xtask scrub` additionally writes a `stream` key to
  `meta.json` as a human-readable summary of the same value, but nothing
  reads it, so a hand-written fixture may omit it.
- `request.json`: the Anthropic request as the client sent it
- `expected-payload.json`: the Kiro payload kiro-trust must produce
- `upstream.eventstream`: raw bytes from the runtime, when the case has a
  response; a transcribed case may instead give `upstream.events.json`, a
  readable list of `{"event_type": .., "payload": ..}` or
  `{"exception_type": .., "payload": ..}` objects, one per frame, that the
  harness re-encodes to the same bytes
- `expected-sse.txt` or `expected-message.json`: the Anthropic output

`tests/fixtures/errors/<case>/` holds a recorded upstream error response
instead: `body.json`, the exact response body bytes, and `meta.json` with
`source`, `status`, `content_type`, and `features`. The fixture harness skips
these directories because they have no `request.json`. The client tests in
`crates/kiro-trust-tests/tests/kiro_client.rs` serve the body with the
recorded status. A recorded error body is saved byte for byte and never
edited; `scripts/check-fixtures.sh` scans it like every other fixture.

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
`<n>-request.json`, `<n>-payload.json`, `<n>-upstream.eventstream`, and
`<n>-response.sse` with mode 0600, in a directory with mode 0700 (created only
when missing; an existing directory keeps its mode, and a pre-existing file or
symlink at one of these four names is never overwritten or followed:
`Capture::write` uses `create_new`, so a restart needs an empty
`--capture-dir`). The feature is off by default, absent from release builds,
and reported by `audit` with exit 1.

`cargo xtask scrub <capture-dir> <fixture-dir> --source "<text>" [--hostname
<name>] [--home <path>] [--name <text>] [--allow-truncated]` replaces the
profile ARN and account id with
`arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE`, conversation
and utterance ids (collected from the request and the Kiro payload, wherever
either key appears) with a fixed id, the home directory with `/home/user`
(matched wherever it occurs, since it is specific enough that a mid-string
match is still the owner's identity), and the hostname with `host`. The
hostname rule matches only as a whole token (so a hostname that is merely a
substring of a longer word is left alone), and tries two candidates, longest
first: the full detected or supplied value, and its first label before a `.`.
`hostname` usually prints only the short label, so if `--hostname` or
detection instead supplies an FQDN, a capture holding only the short label
still has to match; the reverse direction already worked, since the FQDN
occurrence contains the label as a substring.

The home directory and hostname default to `$HOME` and the `hostname`
command's output; `--home`/`--hostname` override either explicitly. Detection
failure aborts the scrub rather than silently scrubbing with an empty rule:
an unset or empty `$HOME`, a missing, failing, or non-UTF-8 `hostname`
command, or an explicitly empty `--home`/`--hostname` value, is a hard error
naming the offending flag.

**An operator recording a fixture must also pass `--name "<their name>"`**
(final-fix-2.md Important 3). Unlike the home directory and hostname, a
personal name has no detectable shape and no `$NAME`-equivalent environment
variable to fall back on, so the scrubber cannot infer it: when `--name` is
omitted, nothing rewrites it. `--name` matches only as a whole token, the
same as the hostname rule, and rewrites to `operator`. Pass the same value to
`FIXTURE_SCRUB_NAME` when running `scripts/check-fixtures.sh` locally against
an unpublished capture, so the scanner checks for the name too.

It writes one case per captured request under `<fixture-dir>/<n>/`:
`meta.json` (`source`, scrubbed like every other field; `features`; `stream`,
the request's own streaming flag), `request.json`, `expected-payload.json`,
`upstream.eventstream` (rewritten frame by frame, so a `messageMetadataEvent`
payload's `conversationId` and `utteranceId` are scrubbed even if the runtime
assigned an id that never appeared in the request), and either
`expected-sse.txt` (streaming, with `msg_` ids masked) or
`expected-message.json` (non-streaming, the folded JSON body scrubbed, its
own `id` field overwritten with the fixture harness's fixed message id since
that harness compares the non-streaming case unmasked) depending on that
same flag, matching which file the fixture harness reads for the case
(section 8.2).

A frame whose payload does not parse as JSON, or a frame `next_frame` itself
fails to decode (a CRC mismatch, for example), aborts the scrub instead of
publishing the unparsed bytes unscrubbed: the frame boundaries are
untrustworthy at that point, so every later frame is lost regardless, and
this is the one case where a partial result would be a leak. A stream
truncated mid-frame is different: the incomplete tail is never written to
any output, so there is nothing to leak. By default it still aborts, so an
operator does not get a silently partial `upstream.eventstream` by accident,
naming `--allow-truncated` as the remedy; with that flag the scrub instead
writes the complete frames decoded so far and prints a warning to stderr
naming the file and the pending byte count. This makes the "cancellation
mid-stream" and "truncated stream" fixture cases (section 8.2) reachable.

`scripts/check-fixtures.sh` fails when any file under `tests/fixtures/`
contains a 12-digit account id, `arn:aws:` outside the fixture ARN, the
owner's home path (with or without a trailing separator), an `aoa`-prefixed
or `eyJ`-prefixed token-shaped string, an email address, or a `kiro.dev`
hostname with a real region other than the fixture's. When
`FIXTURE_SCRUB_NAME` is set it also fails on that exact word, matching
`scrub --name`'s corresponding rule above; unset, it checks nothing for a
name, since (unlike the other rules) there is no shape to check for without
being told what to look for.

Fixtures are public. Record only marker prompts (`kiro-trust fixture probe:
...`) so no real source code enters the repository.

### 8.4 Security tests

One test per line, split across `crates/kiro-trust-tests/tests/security_net.rs`
(net and auth cases, which enable the `test-endpoints` feature from that
crate only) and `crates/kiro-trust-tests/tests/security_logging.rs` (the
logging case):

- `open_writable_is_impossible`: `UPDATE auth_kv` through the connection
  fails with an authorizer denial
- `only_auth_tables_are_readable`: `SELECT` from `history` fails

(unit tests in `crates/kiro-trust-auth/src/db.rs`, since they need the
connection)

- `nothing_sensitive_reaches_the_logs` (`security_logging.rs`): runs real
  `/v1/messages` flows (streaming, folded, an auth failure, and a malformed
  body) at `debug` level against a process-wide capturing subscriber, and
  asserts that none of a marker set covering every spec 6.4 forbidden
  category (headers, prompt, tool name/argument/result, thinking text,
  response text, conversation id, session id, token, home path, database
  path, account id, ARN) appears in any captured log line
- `oidc_redirect_rejected`, `runtime_redirect_rejected`
  (`security_net.rs`): a 302 from a loopback test server is an error and no
  second request is made
- `region_pattern` (`crates/kiro-trust-net/src/region.rs`): `us-east-1/`,
  `evil.com`, `US-EAST-1`, and eight more malformed inputs are all pattern
  errors; `runtime_allowlist` (same file): `ap-southeast-1` is
  pattern-valid but fails the runtime allowlist, both before any hostname
  is built (final-fix-2.md Important 4 renamed this from
  `invalid_region_rejected`, which named no real test)
- `proxy_env_ignored` (`security_net.rs`): with `HTTPS_PROXY` set to a
  listening socket, no connection reaches it
- `only_loopback_addresses_are_accepted`
  (`crates/kiro-trust/src/config.rs`): `0.0.0.0:3456` and
  `192.168.1.10:3456` are config errors (final-fix-2.md Important 4 renamed
  this from `non_loopback_bind_fails`, which named no real test)
- `health_needs_no_token_but_everything_else_does` (`server.rs`): `/health`
  needs no token; a missing token and a wrong one (`Bearer wrong`) both 401
  on every other route; a valid token in either `authorization` or
  `x-api-key` succeeds (final-fix-2.md Important 4 renamed this from three
  names, `missing_token_401`, `wrong_token_401`, and `health_needs_no_token`,
  that named no real tests: all three conditions live in this one test)
- `no_url_in_net_api`: unpinned. No test or CI script currently enforces
  that `Destination` is the only host input in `kiro-trust-net`'s public
  API; it holds today by code review against AGENTS.md's architecture rules
  and spec 3.2 alone (final-fix-2.md Important 4)
- `binary_has_no_dev_features`: `cargo tree -e features -p kiro-trust`
  contains neither `capture` nor `test-endpoints` (script in CI). The check
  and every release build select `-p kiro-trust` alone, because a workspace
  wide build would unify the test crate's features into the binary
- `protocol_crate_is_pure`: `cargo tree -p kiro-trust-protocol` contains no
  `reqwest`, `rusqlite`, `tokio`

### 8.5 Fuzz targets

`fuzz/fuzz_targets/`:

- `frame_decode` (bytes → frames). Generates structurally valid, possibly
  multi-frame streams through the crate's own header/frame encoder, with a
  fuzzer-chosen `(index, byte)` corruption and a trailing-byte truncation
  spliced in, plus a raw-bytes fallback mode for shapes the generator can't
  easily construct on purpose (an inconsistent total/headers length, bytes
  that never form a valid prelude at all). It is not seeded: a mutated seed
  dies at the message CRC exactly as a random one dies at the prelude CRC, so
  a corpus buys nothing the in-process generator doesn't already give.
- `event_parse` (frame → `Event`). Draws the event type from the six literals
  `EventParser::parse` dispatches on (`eventstream.rs:368-424`) plus a
  free-form escape hatch that keeps the unknown-type fallthrough reachable,
  and builds each payload as a JSON object carrying the exact keys that event
  type reads.
- `sse_translate` (event sequence → SSE). Runs every emitted `StreamEvent`
  through `sse::encode` and asserts no panic, the block-state invariants
  (open/close ordering, strictly increasing indices, deltas targeting the
  open block), that the stream starts with `MessageStart`, and that it ends
  with exactly one `MessageStop` and nothing after it.
- `anthropic_request` (bytes → `Request`). The one target seeded from
  fixtures: the CI workflow copies `tests/fixtures/*/request.json` into
  `fuzz/corpus/anthropic_request/` before each run. `tests/fixtures/` is the
  only seed source anywhere in this project; a capture directory is never
  one.
- `tool_input_accumulate` (fragment sequences), payloads built the same way
  as `event_parse`'s.

A weekly CI job runs each target for five minutes on the nightly toolchain,
selected explicitly (`RUSTUP_TOOLCHAIN: nightly`): `dtolnay/rust-toolchain`
only runs `rustup default`, and `rust-toolchain.toml` outranks that for every
directory under the repository, `fuzz/` included, so cargo-fuzz's
nightly-only sanitizer flags need the override or the job silently resolves
to the pinned stable toolchain and fails outright. On failure the workflow
uploads `fuzz/artifacts` only, never `fuzz/corpus`: a crash file is a
regression fixture worth minimizing and committing, but the corpus is
disposable per-run mutation state, and uploading it to a public artifact
store risks it accumulating a real captured payload over time. A pull-request
job (`fuzz-check`) runs `cargo check --manifest-path fuzz/Cargo.toml --locked
--all-targets` on the stable toolchain, so a `kiro-trust-protocol` signature
break is caught immediately rather than only on the next Monday.

### 8.6 Live tier

`crates/kiro-trust-tests/tests/live.rs`, ignored by default, gated on
`KIRO_TRUST_LIVE=1`. Each test reads the real database, sends a marker
prompt, and asserts on structure, never on model wording: streaming text
arrives; a tool call to a `kiro_trust_probe` tool produces `tool_use`; a
thinking request produces a `thinking` block; a non-streaming call returns a
`message` with nonzero `usage.input_tokens`. Live tests print token counts,
byte counts, and durations only, never a prompt, a response body, a
conversation id, a token, an ARN, or an account id.

`history_image_is_accepted` decides whether images ship in history entries
(section 5.3). It sends three messages, a user turn carrying a small synthetic
PNG, an assistant turn, then a user follow-up, so the image lands in a history
entry rather than the current message, and asserts a 200 with a well-formed
stream. The test exists because the Kiro CLI's two code paths disagree about
whether history carries images and neither says why, so the generated SDK
proves the field exists but not that the runtime honors it. The image is
synthetic and a few bytes; it is not a capture and not a credential, so this
test needs no opt-in beyond `KIRO_TRUST_LIVE=1`. Should it fail, history images
stay dropped and the test stays as the record of why.

`forced_refresh_succeeds` sets a validity buffer
(`TokenSource::with_validity_buffer`) longer than any real token lifetime, so
`TokenSource` treats every call as expired and refreshes through AWS OIDC
regardless of how recently the credential was actually issued. It needs a
second, explicit opt-in beyond `KIRO_TRUST_LIVE=1`: `KIRO_TRUST_LIVE_REFRESH=1`.
Both must be `1` for the test to run. This is stricter than the other live
tests because AWS's `CreateToken` reference does not document whether
issuing a new refresh token invalidates the one that was exchanged for it;
see the known limitation in section 12. kiro-trust never persists a refreshed
token (spec 6.1), so a rotated refresh token lives only in this test's
process memory and is discarded when it exits.

This tier has no test for a 403 followed by a successful retry with a fresh
token. That path is covered offline instead, at
`crates/kiro-trust-tests/tests/kiro_client.rs:188-203`
(`retries_throttling_server_errors_and_json_exceptions_but_not_client_errors`),
against a mock upstream that returns a real 403. Forcing an actual 403 from
the live tier would need a production seam to inject a known-bad token into
`TokenSource`, purely for the test; repeatedly presenting invalid credentials
to AWS Identity Center is not something a test suite should do against a real
account.

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
   `target/release/kiro-trust audit --json --kiro-db tests/fixtures/db/idc.sqlite3 --token-file /tmp/kiro-trust-audit/token`.
   `--token-file` points at a scratch path so the gate never touches a real
   runtime token file. The `commit` field is stripped from the output before
   comparing, because it changes on every build and so can never match a
   committed fixture; what remains is compared with
   `tests/fixtures/db/idc-audit.json`.
9. `fuzz-check`: `cargo check --manifest-path fuzz/Cargo.toml --locked
   --all-targets` (8.5), on the stable toolchain since it only needs to
   type-check, not build the sanitizer-instrumented binaries the weekly
   `fuzz.yml` job does.

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
- `include = ["NOTICE"]`: every per-target archive's `[misc]` files are
  `CHANGELOG.md`, `LICENSE`, `NOTICE`, `README.md` (`dist plan` confirms
  it); Apache-2.0 section 4(d) requires a redistribution to carry it, and
  before this it reached only `source.tar.gz`, which packages the whole
  repository regardless of `include`

Every workflow pins actions by commit SHA with the tag in a comment.
`release.yml` is generated by `dist` then hand-edited to `contents: read`
with `write` only on the `host` job; `allow-dirty = ["ci"]` keeps the edits.

Verification a user can run: `gh attestation verify <archive> --owner
dannyota`, and `sha256sum -c`. Attestations cover only the per-target
archives, built and attested in `build-local-artifacts`. The two installers,
`source.tar.gz`, `sha256.sum`, and the SBOM are global artifacts from
`build-global-artifacts`, which does not attest; verify those with
`sha256sum -c` only. This is a deliberate scope, not an oversight:
`build-global-artifacts`'s job is to fetch the already-attested per-target
archive and derive installers and checksums from it, so widening a second
job to `attestations: write`/`id-token: write` would buy little. The SBOM is
a `.cdx.xml` per package on the release: `cargo-cyclonedx`'s own default,
and what `dist`'s generated `release.yml` looks for by name.
`release-preflight.yml` greps the `cargo-cyclonedx` version `release.yml`
pins (currently 0.5.5) out of that file rather than restating it, installs
that exact version, then runs `cargo cyclonedx -v`: the same binary and the
same invocation `release.yml` performs, so a future `dist` regeneration that
bumps the pin cannot silently desync the rehearsal from the real run.
`cargo-auditable` is left unpinned on both sides on purpose: `release.yml`'s
generated matrix expression resolves to a `releases/latest` installer, so
`release-preflight.yml` installing it with `--locked` and no version already
matches; pinning only the preflight side would create the divergence this
paragraph used to have for `cargo-cyclonedx`.

No Homebrew tap and no quarantine removal.

### 9.2 Procedure

`docs/releasing.md` holds the maintainer steps: bump every version field,
add the CHANGELOG entry, push `master`, require CI green on the exact commit,
dispatch `release-preflight.yml` (`cargo publish --workspace --dry-run
--locked --registry crates-io`), `git tag -s vX.Y.Z`, push the tag, confirm
the asset list including attestations and SBOMs. The release ends there.

### 9.3 crates.io

Never automatic. `publish-crates.yml` is dispatched by the owner with the
tag: a `verify` job checks out `refs/tags/<tag>`, requires every version
field to equal the tag, requires a complete GitHub Release (including the
SBOM), checks that all five crates exist on crates.io with owner `dannyota`,
and repeats the dry run; a `publish` job then waits for the `crates-io`
environment approval and publishes through Trusted Publishing. Approval is
per version and never carries forward. Publish order is
`kiro-trust-protocol`, `kiro-trust-net`, `kiro-trust-auth`,
`kiro-trust-kiro`, `kiro-trust`, submitted as one workspace publish. The
first publication of each crate needs a separate owner decision because
Trusted Publishing cannot create a crate.

GitHub auto-creates a referenced environment on first use with zero
protection rules, which would let the first dispatch publish with no
approval and from any ref. Both jobs run
`scripts/check-crates-io-environment.sh`, which fails closed unless
`crates-io` carries a `required_reviewers` rule with at least one reviewer
and a deployment branch policy. When `custom_branch_policies` is set, the
script also verifies deployment branch policies by querying
`GET /repos/{owner}/{repo}/environments/crates-io/deployment-branch-policies`
and requires every entry to be a branch policy named `master`. When
`protected_branches` is set instead, the script delegates the branch-policy
check to the repository's branch-protection settings. That script is a
backstop: the environment's own protection rules, set under Settings >
Environments before the first dispatch, are the actual mechanism that pauses
the job for approval and restricts which ref can reach it.

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
- **Refresh token rotation.** kiro-trust reads the Kiro CLI's stored refresh
  token and, on a refresh, keeps the result in memory only; it never writes
  back (spec 6.1). AWS's `CreateToken` reference does not document whether
  issuing a new refresh token invalidates the one that was exchanged for it,
  so whether Identity Center rotates on use is unknown, and the OIDC guide's
  "Considerations for using this guide" is silent too (both checked
  2026-09-10). Two consequences follow, and they need different answers.

  The first is the owner's: if Identity Center does rotate, a refresh
  performed by kiro-trust leaves the Kiro CLI's own stored refresh token
  stale, and the owner has to log in to Kiro CLI again to restore it. This
  one is accepted, not fixed. Mitigation: kiro-trust refreshes only when the
  credential is within the validity buffer of expiry (5 minutes by default),
  so in ordinary use the Kiro CLI refreshes first, on its own schedule, and
  kiro-trust reads the result the CLI already wrote; kiro-trust's own refresh
  path is reached only when the CLI has not refreshed recently enough, which
  the live tier's `forced_refresh_succeeds` test exercises deliberately (spec
  8.6) and ordinary use should rarely hit.

  The second is kiro-trust's own: a process that refreshes twice must not
  send the same refresh token twice. RFC 6749 section 6 requires a client to
  replace the old refresh token with the one it received, and RFC 9700
  section 4.14 has the authorization server treat a replayed rotated token as
  a stolen-token signal, with revocation of the whole grant as the expected
  response. Re-reading the database at the start of every cycle and
  refreshing from it, which is what kiro-trust and kirocc both did before
  0.3.0, is that replay: it re-sends a token this process already exchanged.
  Should Identity Center ever enforce reuse detection, the cost would be the
  owner's entire Kiro CLI session, which is the outcome this project exists
  to prevent. Section 3.3's three rules are the fix: prefer the database when
  it is fresher, otherwise chain in memory from the newest token held, and
  never fall back to one already exchanged.

  Writing the rotated token back to the database, which is what the Kiro CLI
  itself does (`crates/chat-cli/src/auth/builder_id.rs`, `set_secret` into
  `auth_kv`), is rejected. It would break the read-only contract (6.1) and
  the threat-model row it backs; the CLI owns that schema and migrates it, so
  a writer would be writing into a shape it does not version; two
  uncoordinated writers can clobber each other; and a bug in that writer
  costs the owner their login. It would not even settle the question, since a
  running Kiro CLI holds its own copy in memory and would refresh from that
  regardless of what kiro-trust wrote, leaving two chains on one grant.

  Residual risk, unavoidable without writing: the chain lives only as long as
  the process. After a restart, kiro-trust reads whatever the database holds,
  which may be a token a previous kiro-trust process already exchanged. That
  window is the one replay the design cannot close, and it is bounded by how
  often the proxy restarts without the CLI having refreshed in between. The
  in-process windows are closed rather than accepted: rule 1's strict
  comparison stops a forced cycle from regressing onto an exchanged token, and
  rule 3's burned-seed marker stops a spent seed from being sent again, whether
  it was spent by a successful exchange or by a failure past a 200. Two narrow
  windows stay open by choice, both recorded in rule 3: a refresh that reached
  Identity Center but failed before any response status arrived, and one
  rejected with a non-200 status by an intermediary that had already relayed
  the exchange. Treating either as spent would strand the proxy on ordinary
  transient failures, which is the more likely harm by a wide margin.

## 13. Backlog

Deferred with reasons; each becomes a spec change before code.

| Item | Why deferred |
| --- | --- |
| retry of thinking-only responses (kirocc gate writer) | needs buffered SSE; measure how often Kiro returns no visible text first |
| truncation notice injection | modifies the next prompt; decide after live use |
| binary differential run against kirocc | kirocc cannot target a fake upstream without patching |
| GPT models | different reasoning schema |
| cosign step in addition to attestations | attestations already Sigstore-backed |
| Homebrew tap | must not strip quarantine; needs notarization |
| digest of the stored credential row as the freshness discriminator (3.3) | `expires_at` covers every write the Kiro CLI actually performs; a digest would also catch two writes sharing an expiry, and must never be logged or serialized |
| manual model discovery | needs one successful, structure-only catalog request for each proposed region before any region ships |
| history-image forwarding | needs the structural `history_image_is_accepted` live test after runtime access returns |

# kiro-trust 0.3.0 design

Status: approved for implementation 2026-09-10. This document records the proposed 0.3.0
amendments. The [main spec](kiro-trust-design.md) remains the source of truth until implementation updates that spec in the same
commit as each behavior change. Where this document and the current spec
disagree before then, the current spec wins.

## 1. Goal and scope

Version 0.3.0 makes the proxy easier to inspect and operate while preserving
static inference routing and the read-only credential boundary.

The release contains seven slices:

1. Finish and integrate the in-memory refresh-token chain already designed in
   the main spec. This work is a required baseline, not a second 0.3.0 design.
2. Add offline `models list` and `models show` commands over the compiled
   catalog.
3. Add an explicit `models discover` command that reads upstream availability
   without changing the compiled catalog or inference routing.
4. Add `doctor`, offline by default, with a separate `--network` health probe.
5. Classify throttling more precisely and honor bounded `Retry-After` values.
6. Keep a bounded, process-local usage summary and expose it through an
   authenticated loopback endpoint.
7. Send history images only after the existing live evidence test passes.

GPT support remains deferred. The release does not add model auto-enablement,
remote configuration, persistence, credit estimation, telemetry, a background
service, or a second credential type.

## 2. Proposed security-policy amendments

The current spec forbids model discovery, allows only the OIDC and runtime
hosts, and permits the Kiro bearer token only on runtime requests. Version
0.3.0 cannot add manual discovery without changing those statements. The
implementation must amend the source-of-truth spec explicitly as follows.

| Current guarantee | Proposed narrow exception | Guarantee that remains |
| --- | --- | --- |
| No model discovery, even behind a flag | A foreground `kiro-trust models discover` invocation may call the verified `ListAvailableModels` operation | `serve`, `audit`, `doctor`, `GET /v1/models`, and message inference never discover models |
| Production hosts are OIDC and runtime only | The manual command may call `q.us-east-1.amazonaws.com` or `q.eu-central-1.amazonaws.com`, selected from the profile ARN region | No caller supplies a host, URL, or base URL; redirects, proxies, native roots, and unverified regions remain rejected |
| The bearer token appears only on a runtime request | The manual command may put the bearer token in the `Authorization` header of the fixed model-catalog request | The token appears in no query, body, output, error, or log; the six `expose_secret()` sites remain unchanged |
| No remote configuration | The manual command may print bounded model availability metadata | Nothing is cached, persisted, loaded by the server, or used to resolve an inference model |
| Production networking is HTTPS through fixed upstream destinations | `doctor --network` may send one unauthenticated plaintext request to the configured loopback `SocketAddr`, fixed as `GET /health` | Offline doctor makes no request; no token or caller-selected path, method, host, or header enters the probe |
| Weakening any security contract is a major change | Version 0.3.0 may add only the two exceptions enumerated here: manual discovery to two fixed HTTPS hosts and the optional fixed loopback health probe | Any later destination, credential use, default-path egress, arbitrary target, or weaker authentication remains a major change unless a future major release changes the policy |

This version-policy amendment is part of the proposal. It prevents a narrow,
operator-invoked inspection command from being treated like a silent daemon
egress expansion. The owner approved these amendments with this design on 2026-09-10.

## 3. Model commands

### 3.1 Compiled catalog interface

`kiro-trust-protocol::catalog` remains the only inference catalog. It exposes
owned metadata so the CLI, `GET /v1/models`, request resolution, and usage
indexing read one table:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModelKey { row: u8, context_1m: bool }

impl ModelKey {
    pub fn catalog_index(self) -> usize;
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ModelInfo {
    #[serde(skip)]
    pub key: ModelKey,
    pub id: String,
    pub display_name: String,
    pub kiro_model: String,
    pub aliases: Vec<String>,
    pub accepts_date_suffix: bool,
    pub context_window: u32,
    pub effort_levels: Vec<String>,
    pub proxy_input_types: Vec<String>,
    pub history_images_forwarded: bool,
}

pub fn models() -> Vec<ModelInfo>;
pub fn model(model: &str) -> Result<ModelInfo, UnknownModel>;
pub fn supports_kiro_model(model_id: &str) -> bool;
```

`Resolved` gains `key: ModelKey`. `ModelKey` has private fields and no public
constructor. The catalog constructs keys only for valid row and context-tier
pairs; `catalog_index()` maps those pairs to fixed aggregate slots. Usage
aggregation cannot create keys from caller text. `ModelKey` is skipped in
serialized `ModelInfo`.

`proxy_input_types` is `text,image` for the current catalog. The field reports
what the proxy accepts and forwards, not a per-model vision claim.
`history_images_forwarded` remains `false` until section 7's live gate passes,
then changes globally because translator behavior is global. The single Sonnet
evidence test proves the disputed history wire field on that route. It does not
prove every catalog model understands image content. The CLI does not infer
image support from a remote discovery response.

`models()` emits one entry per routable row and context tier, in catalog order,
with the default tier before a separate 1M tier. Each entry's id equals
`Resolved.anthropic_model`. Aliases are concrete strings that resolve to that
same key: canonical ids, Kiro SKUs, and dashed or dotted forms. A `[1m]` alias
belongs to the tier it resolves to. `accepts_date_suffix` describes the existing
eight-digit suffix rule separately; aliases never contain a placeholder date.

### 3.2 Offline commands

Command shapes:

```text
kiro-trust models list [--json]
kiro-trust models show <model> [--json]
```

Both commands are offline. They do not open the Kiro database, read a token,
contact a listener, or create a network client.

Text `list` output has `ID`, `KIRO MODEL`, `CONTEXT`, `INPUTS`, and `EFFORT`
columns. JSON is `{"object":"model_catalog","models":[ModelInfo...]}` in
catalog order. Text `show` prints each `ModelInfo` field in a stable order.
JSON is the selected `ModelInfo`. An unknown id exits 1 and prints the fixed
error `kiro-trust: unknown model; run 'kiro-trust models list' for supported
models`. The error never echoes the caller's input.

### 3.3 Manual discovery

Command shape:

```text
kiro-trust models discover [--json] [--kiro-db <path>] [--extra-ca <pem>]
```

The command runs once, prints the result, and exits. It never runs during
`serve`, `audit`, `doctor`, `GET /v1/models`, request resolution, or startup.
It never writes a cache or catalog file.

The AWS [`amazon-q-developer-cli` source](https://github.com/aws/amazon-q-developer-cli/tree/15cc8f3cd18c4272925ce1c7053268eedff1ea0a)
at commit `15cc8f3cd18c4272925ce1c7053268eedff1ea0a` verifies this wire shape:

- `crates/chat-cli/src/api_client/endpoints.rs` names
  `https://q.us-east-1.amazonaws.com` and
  `https://q.eu-central-1.amazonaws.com/`.
- `crates/chat-cli/src/api_client/mod.rs` selects the endpoint from the
  profile region, configures bearer authentication, sets origin `CLI` and
  profile ARN, and paginates.
- `crates/chat-cli/src/auth/builder_id.rs` loads the credential before API
  use, refreshes an expired access token through `CreateToken`, and saves the
  returned credential. Kirocc v0.11.1 `internal/auth/refresh.go` also refreshes
  an expired credential before API use and caches the result in memory.
- `crates/amzn-codewhisperer-client/src/operation/list_available_models.rs`
  sends `POST /` with the same input fields in the query and JSON body,
  `Content-Type: application/x-amz-json-1.0`, and
  `x-amz-target: AmazonCodeWhispererService.ListAvailableModels`.
- The generated input and output shapes carry `origin`, `maxResults`,
  `nextToken`, `profileArn`, and `modelProvider`; the output carries `models`,
  `defaultModel`, and `nextToken`.
- The generated `Model` shape carries `modelId`, `modelName`, `description`,
  `rateMultiplier`, `rateUnit`, `tokenLimits`, `supportedInputTypes`, and
  `supportsPromptCache`. It carries no effort metadata.

The implementation sends `origin=CLI`, `profileArn`, and `nextToken` when a
next token exists. It sends no `maxResults` or `modelProvider`, because the
shipped CLI does not set them. The query and JSON body contain the same
values. Query construction percent-encodes values and is confined to a fixed
`ModelDiscoveryQuery` type in `kiro-trust-net`; callers cannot pass a raw
query, URL, host, path, or key name.

`Client::post_model_discovery(&Destination, ModelDiscoveryQuery,
SensitiveBearer) -> Result<Response, NetError>` accepts no caller headers or
body. The transport builds the fixed path, headers, query, and JSON from the
typed input. `SensitiveBearer::new(&str)` runs inside `with_token`, validates
the header value, and marks it sensitive. The wrapper has no `Debug`,
`Display`, or `Serialize` implementation. Generic `Client::post` rejects
`Destination::ModelCatalog`, so callers cannot bypass the fixed operation.

`Destination::ModelCatalog` accepts only `us-east-1` and `eu-central-1`.
The compiled enabled-region subset contains only regions whose live gate has
passed; other recognized regions fail before transport with `region_unverified`.
The database reader parses and retains the profile ARN region as a typed,
non-secret `Identity.profile_region: Option<Region>`. The existing identity
keeps the profile ARN for request construction only. Discovery rejects a
missing profile region without changing ordinary runtime credential parsing.
Discovery selects this profile region, not the token region, runtime
fallback, or a command-line override. It does not
copy the upstream CLI's fallback to US East when selection fails. A government
region or any future unverified region exits 1 before a catalog request and names the
two supported discovery regions.

The generated source verifies the request shape, but source inspection cannot
prove that the owner's Identity Center profile may call the operation. Before
shipping a discovery region, a live evidence test must prove one successful
page for that region with an authorized profile. A source-verified region with
no live evidence remains disabled in the release. The test asserts status and
structure and prints only counts and durations. If the account receives access denied, that
region remains unshipped until the endpoint, permission, and credential scope
are verified. No host is guessed.

### 3.4 Discovery credential safety

Discovery creates one ordinary `Arc<TokenSource>` with
`TokenSource::new(db_path, net.clone(), None)` and shares it across identity
lookup and every catalog page. The existing five-minute validity buffer
triggers OIDC refresh when needed. All pages use the same in-memory token
chain. An expired access token alone does not require a new Kiro CLI login.

Catalog responses do not trigger refresh. Discovery never calls `invalidate()`
or retries authentication after a catalog response. A catalog 401 maps to
`DiscoveryError::Authentication`; a catalog 403 maps to
`DiscoveryError::AccessDenied`. Token-source and OIDC errors map to the fixed
`Authentication` error without exposing their remote text.

The 30-second operation deadline starts before the first `TokenSource` call
and includes identity lookup, OIDC refresh, and every page. The OIDC exchange
retains its own inner cap. The existing cancellation guard records a spent
refresh seed when a 200 OIDC status arrived before cancellation. No new auth
mode or production `expose_secret()` site is added. The database stays read-only.

Each standalone discovery command owns a separate in-memory chain. Commit
`66d9dd3` prevents replay within one `TokenSource`; it does not coordinate
different processes or survive a restart. If Identity Center rotates refresh
tokens and detects reuse, discovery can replay a database token another process
already exchanged, or exit while the database still holds an older token.
AWS's rotation behavior remains unknown. Main spec section 12 already accepts
this risk for independent processes and restarts; discovery increases how often
those processes start. No credential broker or database writer is added.

### 3.5 Discovery bounds and output

The client accepts at most 16 pages, 512 distinct models, 1 MiB per response
page, a 256-byte model id, a 4 KiB next token, and 30 seconds for the complete
operation across all pages. A repeated next token, duplicate model id with
different metadata, missing or conflicting `defaultModel`, or invalid token
limit is a protocol error. A bound breach returns `LimitExceeded`.
Identical duplicate rows collapse by model id.
Present token limits must be positive integers that fit `u32`; missing limits
remain null. A present rate multiplier must be finite and nonnegative. Page
collection uses a separate bounded response reader; the existing 64 KiB error
body limit stays unchanged.

The parser rejects a model id containing ASCII control characters, terminal
escape bytes, `arn:`, a bare 12-digit run, or an `aoa`- or `eyJ`-prefixed
token-shaped value. Free-form model names, descriptions, rate units, unknown
input type strings, and upstream error messages never reach either output
form. Known input types map to the bounded values `text` and `image`; every
other value maps to the literal `unknown`. Discovery errors are fixed local
classes. Apply the same id validator to `defaultModel.modelId`; it must match
one of the collected rows. Reject malformed defaults before either output
renderer runs.

Text output includes `AVAILABLE ID`, `CATALOG STATUS`, `INPUTS`, `INPUT LIMIT`,
`OUTPUT LIMIT`, and `PROMPT CACHE`. JSON uses:

```json
{
  "object": "discovered_models",
  "region": "us-east-1",
  "default_model": "remote-id",
  "models": [
    {
      "id": "remote-id",
      "available": true,
      "catalog_status": "not_listed",
      "input_types": ["text"],
      "max_input_tokens": 200000,
      "max_output_tokens": 8192,
      "supports_prompt_cache": true,
      "rate_multiplier": null
    }
  ]
}
```

`catalog_status` is `supported` only when the compiled catalog accepts that
exact Kiro model id; otherwise it is `not_listed`. `not_listed` means the proxy
cannot route that id, not that generation is unusable in another client.
Remote effort is omitted because the upstream shape does not carry it. Neither
form prints names, descriptions, rate units, unknown input strings, profile
ARN, account id, pagination tokens, headers, raw bodies, bearer tokens, or raw
upstream error messages.

`DiscoveryReport` has the fields shown in the JSON example: `object` is the
fixed `discovered_models` string, `region` and `default_model` are validated
strings, and `models` is `Vec<DiscoveredModel>`. `DiscoveredModel` has
`id: String`, `available: bool` (always true), `catalog_status: CatalogStatus`,
`input_types: Vec<DiscoveryInputType>`, `max_input_tokens: Option<u32>`,
`max_output_tokens: Option<u32>`, `supports_prompt_cache: Option<bool>`, and
`rate_multiplier: Option<f64>`. The enums serialize as `supported|not_listed`
and `text|image|unknown`. Deduplicate input types and emit them in that order.
`DiscoveryError` is a fixed enum: `Authentication`, `AccessDenied`,
`RegionUnverified`, `Transport`, `Protocol`, and `LimitExceeded`. It carries no
remote body, header, identifier, or parser error text.

## 4. Doctor

Command shape:

```text
kiro-trust doctor [--json] [--network] [--listen <loopback-address>]
                  [--kiro-db <path>] [--runtime-region <region>]
                  [--token-file <path>] [--extra-ca <pem>]
```

`doctor` reuses the `serve` settings for listener, database, runtime-region,
token-file, and extra CA. It is offline unless `--network` is present. The
offline run performs these checks in order:

1. Parse the loopback address and runtime-region override, resolve the
   database and token-file paths, and parse the extra CA when configured.
2. Open the database through `KiroDb::open_read_only`, verify `query_only`,
   and parse the Identity Center credential.
3. Report the token expiry as `valid`, `refresh_required`, or `expired`.
   `refresh_required` means five minutes or less remain. Doctor never refreshes.
4. Inspect the local token file without reading its contents. On Unix it must
   be a regular file with no group or other permission bits. On Windows it
   reports that access-control-list permissions are not verified by this
   version. When `KIRO_TRUST_TOKEN` is set, doctor reports an explicit token
   configuration without reading its value.
5. Report listener reachability as `skipped` in offline mode. A valid address
   is configuration evidence, not reachability evidence.

`--network` adds one request: unauthenticated `GET /health` to the configured
loopback address. `kiro-trust-net::probe_loopback_health(SocketAddr)` builds a
private reqwest client with proxies and redirects disabled, fixed `/health`,
HTTP/1, a two-second connect timeout, a two-second response timeout, and a
256-byte body limit. The function rejects non-loopback addresses again. It
sends no local or Kiro token and accepts only status 200 with
`application/json` and `{"status":"ok"}`.

The text and JSON forms contain checks with `ok`, `warning`, `error`, or
`skipped` status and a fixed detail string. Exit 1 means at least one check is
`error`; warnings and skips exit 0. Clap usage errors exit 2. Paths use the
same home abbreviation as audit. No ARN, account id, token, header value,
database value, or raw network body reaches output.

`DoctorReport` contains `version: String`, `paths: DoctorPaths`, and
`checks: Vec<DoctorCheck>`. `DoctorPaths` has `database`, `token_file`, and
`extra_ca`, each `Option<String>`; unresolved or absent paths are null. Apply
audit's home abbreviation before constructing these fields. Text prints the
three named paths first and uses `none` for null.
`DoctorCheck` contains `name: DoctorCheckName`, `status: DoctorStatus`, and
`detail: DoctorDetail`. All three enums serialize to snake-case strings.
There are no free-form error strings in the report. Text output renders
`NAME STATUS DETAIL` in the order below. The `name` values are fixed:
`configuration`, `database`, `credential_expiry`, `local_token`, and `listener`.

| Check and condition | Status | Detail |
| --- | --- | --- |
| Configuration parses and optional CA loads | ok | valid |
| Invalid loopback, region, path resolution, or CA | error | invalid_configuration |
| Database opens read-only and credential parses | ok | read_only |
| Database missing or unreadable | error | database_unavailable |
| Read-only assertion or credential parsing fails | error | credential_invalid |
| More than five minutes until expiry | ok | valid |
| Positive expiry interval at most five minutes | warning | refresh_required |
| Expiry reached or timestamp unavailable | warning | expired |
| Credential unavailable | skipped | credential_unavailable |
| Explicit local token variable is present | ok | explicit_token_configured |
| Token file is a regular Unix file with no group/other bits | ok | private_file |
| Token file missing | warning | token_file_missing |
| Token file metadata unreadable | error | token_metadata_unreadable |
| Token file is a symlink, nonregular, or has Unix group/other bits | error | unsafe_token_file |
| Regular Windows token file | warning | acl_not_verified |
| Offline listener check | skipped | network_disabled |
| Network probe succeeds | ok | healthy |
| Any network probe failure | error | health_probe_failed |
| Invalid configuration prevents a dependent check | skipped | invalid_configuration |

Use `symlink_metadata` for local token inspection. An explicit token variable
skips file inspection. Continue independent checks after errors, and skip only
checks whose prerequisites failed. Missing token files are warnings because
`serve` creates them. Expiry warnings do not claim refresh will succeed.

## 5. Throttling, quota, and retry

### 5.1 Classification

The public API continues to use HTTP 429 `rate_limit_error`, but the normalized
message and usage category distinguish:

| Category | Evidence | Retry |
| --- | --- | --- |
| `local_concurrency` | The 32-request semaphore has no permit | Never inside the proxy; return 429 with `Retry-After: 1` |
| `model_capacity` | The bounded upstream error body contains the exact marker `INSUFFICIENT_MODEL_CAPACITY` | Transient; use the retry schedule |
| `allowance_exhausted` | The bounded upstream error body contains the exact marker `MONTHLY_REQUEST_COUNT` | Never; return 429 immediately |
| `transient_throttle` | 429, `ThrottlingException`, or `TooManyRequestsException` without the monthly marker | Transient; use the retry schedule |

The retry schedule belongs to `KiroClient::generate()` and applies to retryable
HTTP errors and decoded non-eventstream JSON exceptions. The server adds no
transient retry loop for exception frames. Its only replay remains the one
permitted for the three invalid-state reasons in the main spec. A capacity
exception frame before output becomes a normalized HTTP error; after output
it becomes the corresponding SSE error.

HTTP 429 applies before response headers are sent. After streaming starts, emit
the normalized SSE error and keep the existing HTTP status; neither a new
status nor `Retry-After` can be sent after headers.

The two exact markers come from the Kiro CLI source at the pinned commit,
`crates/chat-cli/src/api_client/mod.rs`. Arbitrary words such as `quota`,
`limit`, or every 429 never establish allowance exhaustion. A scrubbed,
recorded response fixture must verify the exact monthly marker before
`allowance_exhausted` ships. Until that fixture exists, the classifier treats
the response as `transient_throttle`.

### 5.2 Retry-After

For a retryable 429 or 5xx, parse `Retry-After` as [RFC 9110 section 10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after) permits: an integer
delay in seconds or an HTTP date. Add a direct `httpdate = "1.0.3"` dependency
to `kiro-trust-kiro`; do not hand-write HTTP-date parsing. Invalid, negative,
or past values fall back to exponential jitter. An all-digit value too large
to fit `u64` is an excessive delay: stop retrying and omit the unrepresentable
local header. A valid delay at most 60
seconds replaces exponential jitter. A delay over 60 seconds is not slept or
shortened: stop retrying and return the normalized error with the remaining
delay, rounded up to seconds, in the local `Retry-After` response header.

`UpstreamError` gains `attempts: u32` and `retry_after: Option<Duration>`.
An attempt is a completed `net.post()` call, whether it returns a response or
a transport error. Increment after that future returns. Credential/header
failures before the call count zero; cancelling a pending call does not prove
a completed attempt. Every return path carries the accumulated count. This makes failed
requests account for retries as accurately as successful `UpstreamStream`
values. Debug and display never print an upstream header value.

### 5.3 Attempt progress during cancellation

A returned `generate()` result cannot report attempts completed before that
future was cancelled. `kiro-trust-kiro` provides a cloneable `AttemptProgress`
handle containing one saturating `AtomicU32` counter. `completed()` reads the
count; `record_completed(count)` adds completed attempts. The handle carries
no request, credential, model, or error data.

`Upstream::generate_with_progress(&Payload, &AttemptProgress)` defaults to
calling `generate()` and adding the returned stream or error's `attempts`.
Existing test doubles remain source-compatible. `KiroClient` overrides the
method and uses the same retry loop as `generate()`. That loop increments
progress immediately after each `net.post().await` returns, before another
await or response inspection. Pending calls and pre-send failures add zero.
Returned stream and error counts remain per-call; the shared handle is
cumulative across the one permitted invalid-state replay. No count is added
twice. `MAX_ATTEMPTS` remains three.

Cancellation during retry sleep or a pending second send retains one completed
attempt and zero retries. Cancellation after two completed posts retains two
attempts and one retry. Counting begins only when a post returns, regardless
of whether a pending call may already have sent bytes.

## 6. In-memory usage summary

### 6.1 Boundary and endpoint

`AppState` owns `Arc<UsageSummary>`. The summary starts empty when `serve`
starts and disappears when the process exits. It has no file, database,
telemetry, exporter, reset route, or CLI command.

Authenticated `GET /v1/usage` returns a snapshot. The existing local-token
middleware protects it. The route never contacts Kiro and the route request
does not count as model usage.

The response is:

```json
{
  "object": "usage_summary",
  "since": "2026-09-10T00:00:00Z",
  "requests": {
    "started": 0,
    "completed": 0,
    "failed": 0,
    "cancelled": 0,
    "in_flight": 0
  },
  "tokens": {
    "reported": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
    "estimated": {"input": 0, "output": 0}
  },
  "duration_ms": {"total": 0, "max": 0},
  "retries": 0,
  "errors": [],
  "models": []
}
```

Each `models` entry contains `id`, `requests`, `tokens`, `duration_ms`,
`retries`, and `errors`, using the same counter shapes as the top level. Storage
uses `ModelKey` and omits zero-count slots. The catalog id is rendered only when
the snapshot is built. Each `errors` entry is `{"kind":"transport","count":1}`;
zero-count categories are omitted and entries follow enum order. The fixed
categories are `local_concurrency`, `authentication`, `model_capacity`,
`allowance_exhausted`, `transient_throttle`, `upstream_server`, `transport`,
`protocol`, `invalid_state`, `invalid_request`, and `cancelled`. Counters and sums saturate at
`u64::MAX`. The fixed model keys and error enum bound cardinality.

The response describes observed proxy activity. It never claims current or
remaining Kiro credits. The upstream `meteringEvent.credits` value remains
ignored because its unit and relation to allowance are not verified.

The server response structs use these exact field shapes. Derive `Serialize`
for each; `UsageErrorKind` serializes its fixed variants in snake case.

```rust
pub struct RequestCounts {
    pub started: u64, pub completed: u64, pub failed: u64,
    pub cancelled: u64, pub in_flight: u64,
}
pub struct DurationCounts { pub total: u64, pub max: u64 }
pub struct ErrorCount { pub kind: UsageErrorKind, pub count: u64 }
pub struct UsageTotals {
    pub requests: RequestCounts,
    pub tokens: UsageSnapshot,
    pub duration_ms: DurationCounts,
    pub retries: u64,
    pub errors: Vec<ErrorCount>,
}
pub struct ModelUsageReport {
    pub id: String,
    #[serde(flatten)] pub totals: UsageTotals,
}
pub struct UsageReport {
    pub object: &'static str,
    pub since: String,
    #[serde(flatten)] pub totals: UsageTotals,
    pub models: Vec<ModelUsageReport>,
}
```

### 6.2 Token source and request lifetime

`ResponseTranslator::usage_snapshot()` returns separate buckets:

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReportedTokens {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct EstimatedTokens { pub input: u64, pub output: u64 }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct UsageSnapshot {
    pub reported: ReportedTokens,
    pub estimated: EstimatedTokens,
}
```

When either upstream input or output count is nonzero, put both upstream
counts in `reported`; otherwise put the current input/output estimates in
`estimated`. Cache counts always go in `reported`, including a cache-only
metadata event whose input/output counts still use estimates. A new snapshot
replaces the previous snapshot; it is not a delta to add. Preserve the existing
Anthropic `usage()` output.

`RequestUsageGuard` begins after envelope validation and model resolution but
before the concurrency permit is attempted. It therefore counts a valid-model
local-concurrency rejection. It carries `ModelKey`, start time, latest usage
snapshot, output bytes, and an `AttemptProgress` handle. Exactly one terminal method records
`completed` or `failed`. `Drop` records `cancelled` only when no terminal
method ran.

Later payload/image validation failures count as `failed` with the fixed
`invalid_request` category. Upstream identity or token failure counts as
`authentication`. Requests rejected by local-token middleware or rejected before
model resolution remain outside the summary. Each such return is explicit;
`Drop` is reserved for cancellation, not error propagation through `?`.

For streaming, seed the guard from the primed pump before constructing the
response body. The guard owns the entire body lifetime, including the initial
event batch, beside the semaphore permit. Each chunk updates its snapshot.
Record completion when the terminal event is yielded, without requiring a
later poll for EOF. Normal end marks completed,
a translated or transport error marks failed, and client body cancellation
drops the state and marks cancelled. For non-streaming, every return after the
guard starts calls a terminal method. Validation failures before the guard are
outside the summary because no bounded `ModelKey` exists for an unknown model.

Sum completed transport attempts across all `generate` calls, including the
one permitted invalid-state replay. Retries equal that sum minus one, saturated
at zero; do not add a separate replay count. Failed `generate` calls use `UpstreamError.attempts`, so
their retries are not lost. Count tokens from the final observed attempt only;
discarded invalid-state attempts contribute retries and duration, not token
estimates. This summary measures proxy activity, not total upstream billing.

The guard exposes a cloned handle through `attempt_progress()` and reads
`completed().saturating_sub(1)` at completion, failure, and cancellation.
`server::messages` passes the same handle to every `generate_with_progress()`
call. `update(&mut self, UsageSnapshot, u64)` replaces the token snapshot and
output-byte count; it takes no separate retry snapshot. Existing terminal log
paths read the same progress count. Cancellation adds no log.

The aggregate updates `started` and `in_flight` at begin. It adds the latest
token snapshot, retries, and elapsed duration only at the terminal transition,
which decrements `in_flight` and increments exactly one outcome. Failed and
cancelled outcomes also increment one fixed error category. In-flight requests
contribute no token or duration totals yet. One mutex protects global and
per-model updates and snapshots. Before saturation,
`started = completed + failed + cancelled + in_flight`; all arithmetic saturates
independently after `u64::MAX`, so that equality is not promised after saturation.

## 7. History images

The existing ignored `history_image_is_accepted` test is the gate. The test
must continue to build `Payload` directly so it inserts a history image even
while `build_payload` still drops one. Routing the evidence test through the
translator would let it pass without exercising the disputed wire field.

The owner's runtime allowance is exhausted as of 2026-09-10. No runtime live
test runs until the allowance resets. The exhaustion says nothing about
whether history images are accepted.

After reset, run only the existing structural live test first. A pass permits
the translator change: history user entries scan and validate images exactly
like the current message, promote images from tool results, allow at most ten
images across the request and 10 MiB (10,485,760 decoded bytes) per image. Set the global proxy
capability `ModelInfo.history_images_forwarded = true`. The evidence covers the
tested Sonnet route and the translator wire shape; it is not a per-model vision
claim. A failure keeps history images dropped,
keeps the test as evidence, and updates the main spec to state the observed
runtime behavior. It does not trigger a workaround or guessed alternate wire
shape.

## 8. Errors, logging, and bounds

All new errors use the existing exit codes and Anthropic envelope rules.
Discovery and doctor use fixed local error classes and never display upstream
messages or raw bodies. Model ids and other remote text
are length-bounded before storage or display. Text output escapes control
characters.

No new log field is required. Existing `attempt`, `retry_count`, token counts,
duration, status, and `error_type` fields cover the changes. Error types come
from fixed enums. No prompt, tool name, tool data, model discovery description,
profile ARN, account id, header value, token, pagination token, or raw body is
logged.

The protocol crate remains pure. `reqwest` remains in `kiro-trust-net` only.
Public network APIs name non-loopback hosts through `Destination` only.
`probe_loopback_health(SocketAddr)` is the sole exception: it accepts only a
configured loopback address and sends the fixed unauthenticated health request
defined in section 4. The binary never enables `test-endpoints`. The six
production `expose_secret()` sites remain the exact list in the current spec.

## 9. Evidence and release gates

The offline gate is:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace -- --test-threads=6
cargo deny check advisories bans licenses sources
./scripts/check-packages.sh
./scripts/check-fixtures.sh
./scripts/check-features.sh
cargo build --release --locked -p kiro-trust
```

The release and feature checks select `-p kiro-trust`, not a workspace build,
so test-crate features do not unify into the binary.

Three evidence gates remain:

1. `models discover` needs one successful, structure-only live call for each
   region enabled in the release. Access denied leaves that region gated. An
   offline injected transport test proves expiry refresh occurs once across
   two pages and catalog 401/403 responses never trigger another refresh.
2. `allowance_exhausted` needs a scrubbed fixture containing the exact
   `MONTHLY_REQUEST_COUNT` marker. A generic 429 fixture proves only transient
   throttling.
3. History images need the existing `history_image_is_accepted` test after the
   allowance resets.

The ordinary live suite remains blocked while the allowance is exhausted.
Forced refresh is a separate service and runs only with both opt-ins:

```bash
KIRO_TRUST_LIVE=1 KIRO_TRUST_LIVE_REFRESH=1 \
  cargo test --workspace forced_refresh_succeeds -- --ignored --test-threads=1
```

Before release, run the checks in `docs/releasing.md`, including
`cargo publish --workspace --dry-run --locked`. The release ends at the signed
tag and GitHub Release assets. A crates.io upload is not in this plan and needs
the owner's separate approval for version 0.3.0.

Each implemented slice receives an independent Sol review after its tests pass
and before dependent work starts. A design or review worker must not implement
the same slice.

The discovery and doctor slices update `AGENTS.md`, `audit`, its synthetic JSON
fixture, `docs/security.md`, and `docs/threat-model.md` in the same commits as their policy
changes. Audit must distinguish disabled automatic discovery from explicit
manual discovery and list the command-scoped destinations. A later release
documentation task cannot repair a false security claim in an earlier commit.

Audit keeps `allowed_outbound` scoped to the configured `serve` hosts. It adds
`manual_discovery_outbound: Vec<String>`, populated with enabled catalog hosts,
and `doctor_network: String`, equal to `"explicit unauthenticated GET /health to configured loopback"`.
`dynamic_model_discovery` becomes `"automatic disabled; manual command only"`
when discovery ships, or remains `"disabled"` when it is deferred. Text labels
are `Serve outbound`, `Manual discovery outbound`, `Doctor network`, and
`Dynamic model discovery`. Empty manual destinations print `none`. Audit
derives the destination list from the same compiled region policy as discovery;
audit performs no probe or discovery request.

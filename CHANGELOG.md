# Changelog

All notable changes to kiro-trust. Dates are UTC.

## 0.3.0 - 2026-09-10

- `kiro-trust models list [--json]` and `kiro-trust models show <model>
  [--json]` inspect the compiled catalog without credentials or network access.
  The catalog reports routable models and their context tiers, inputs, effort
  levels, aliases, and history-image forwarding state. It does not report
  remote availability or enable a model.
- `kiro-trust doctor [--json] [--network]` checks local configuration,
  read-only credential access, expiry, and local-token metadata. It is offline
  by default. `--network` permits one fixed, unauthenticated loopback
  `GET /health` reachability probe with a two-second total deadline.
- `GET /v1/usage` returns an authenticated, process-local summary of observed
  proxy activity. The summary starts empty on `serve`, disappears when the
  process exits, and separates upstream-reported token counts from local
  estimates. It never reports remaining Kiro credits.
- Retryable 429 and 5xx responses honor bounded `Retry-After` values.
  `INSUFFICIENT_MODEL_CAPACITY` receives the `model_capacity` classification.
  Each `generate` call allows at most three upstream attempts and counts
  completed posts through cancellation. The permitted invalid-state replay can
  make one additional `generate` call.
- The refresh chain retains the newest credential in memory after an OIDC
  refresh, avoiding replay of a refresh token already exchanged by this
  process. It does not write the Kiro CLI database or coordinate separate
  processes.
- Manual model discovery, monthly allowance classification, and history-image
  forwarding remain deferred behind their separate evidence gates.

## 0.2.0 - 2026-09-10

- `kiro-trust exec -- <cmd> [args...]` runs a command with
  `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` in its environment and
  nothing else changed. Compared with `eval "$(kiro-trust env)"`, the token
  never enters a shell or a shell history. On Unix it replaces itself with the
  child, so no wrapper process survives holding the token.
- `--extra-ca <pem>` adds trust anchors from one PEM file to the compiled
  roots, never replacing them, for networks that terminate TLS at an
  inspecting middlebox. A missing, unreadable, malformed, or oversized file is
  a startup error, never a silent fallback, and `audit` shows the configured
  path so the deviation is visible.
- The listener bounds connections that never reach a handler: at most 32
  concurrent connections, and a 15-second deadline for a connection's first
  request to be parsed. `audit` reports both.

## 0.1.0 - 2026-09-09

First release.

- `kiro-trust serve`: a loopback Anthropic Messages API proxy for Claude
  Code. It reads the Kiro CLI's AWS IAM Identity Center credential
  read-only, refreshes it through AWS OIDC when it is near expiry, and
  translates requests and streamed responses to and from the Kiro runtime
  protocol.
- Security guarantees: loopback-only listener with a mandatory local token;
  read-only credential access limited to the Identity Center rows; outbound
  traffic limited to the OIDC and Kiro runtime hosts, with no redirects, no
  proxy, and compiled-in TLS roots; no request or response body logging and
  no flag to enable one; no telemetry, crash reporting, update checks, or
  dynamic model discovery. `kiro-trust audit` reports the checkable subset
  of these against the running build and exits 1 if one fails.
- Command surface: `serve`, `env` (prints the shell exports `eval` needs),
  `audit` (`--json` optional).
- Known limitations: no social login or Kiro API keys, no GPT models, no
  proxy-side Tool Search or Advisor, no dynamic model discovery, no web UI,
  remote listener, or multi-user support. See the README's Limitations
  section and design spec section 1 for the complete, reasoned list.
- Attribution: protocol behavior is transcribed in part from
  [d-kuro/kirocc](https://github.com/d-kuro/kirocc), used as a test oracle;
  see `NOTICE`.
- Release tooling: cargo-dist cross-platform builds with attestations and
  SBOMs, a release preflight check, and an owner-gated crates.io publish
  workflow.

# Changelog

All notable changes to kiro-trust. Dates are UTC.

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

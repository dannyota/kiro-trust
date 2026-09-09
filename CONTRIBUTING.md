# Contributing to kiro-trust

## Setup

Requires the pinned Rust toolchain (`rust-toolchain.toml` installs it).

```bash
git clone https://github.com/dannyota/kiro-trust
cd kiro-trust
cargo test --workspace -- --test-threads=6
```

`cargo test` needs no Kiro login. The live tier reads the Kiro CLI database
and is opt-in: `KIRO_TRUST_LIVE=1 cargo test --workspace -- --ignored --test-threads=1`.
That command still skips `forced_refresh_succeeds`, which forces a real OIDC
refresh and needs a second, explicit `KIRO_TRUST_LIVE_REFRESH=1` alongside
`KIRO_TRUST_LIVE=1` (spec 8.6).

## Read the spec before changing behavior

`docs/specs/kiro-trust-design.md` is the source of truth for scope,
architecture, security contracts, and verified protocol facts. When code and
spec disagree, the spec wins and the fix lands in the spec first, in the same
commit as the behavior change.

## Gates

CI runs all of these. Run them before opening a pull request.

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo deny check advisories bans licenses sources
./scripts/check-packages.sh && ./scripts/check-fixtures.sh && ./scripts/check-features.sh
```

## What review will hold you to

The reasoning is in the spec, sections 3 and 6. The rules:

- Dependency direction is one way; `reqwest` lives in `kiro-trust-net` only.
- Hosts come from `Destination` only. No URL type in a public API.
- Secrets are `SecretString`; bodies and header values are never logged.
- The Kiro database is opened read-only through one constructor and only
  `auth_kv` and `state` are read.
- The listener is loopback only and every route but `/health` needs the local
  token.
- Unknown models fail with 400; nothing falls back to a default model.

## Fixtures are captured, then scrubbed

`tests/fixtures/` holds captures from the Kiro runtime scrubbed by
`cargo xtask scrub`, plus regression cases transcribed from kirocc tests. Do
not hand-edit a captured fixture to make a test pass; re-capture and re-scrub.
Fixtures are public: record only marker prompts.

## Releasing

Maintainers only: `docs/releasing.md`.

## Agents

Agent guidance lives in the tracked `AGENTS.md`. Durable rules belong in this
file or the spec.

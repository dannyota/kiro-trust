<!-- Keep under 200 lines. Include only rules easy to violate, not facts derivable from code or the spec. -->

# kiro-trust

Rust local trust proxy: Claude Code speaks the Anthropic Messages API to a
loopback listener; kiro-trust reads the Kiro CLI credential read-only,
refreshes it through AWS IAM Identity Center, and talks to the Kiro runtime.
It is the only process that holds the Kiro bearer token. Sibling projects by
the same owner, [elasticctl](https://github.com/dannyota/elasticctl) and
[splunkctl](https://github.com/dannyota/splunkctl), set the operating style.

**Read `docs/specs/kiro-trust-design.md` before changing anything.** It defines
scope, architecture, security contracts, and verified protocol facts. When code
and spec disagree, the spec wins. Update the spec first and in the same commit
as any behavior change. Remove closed items from the backlog (spec section 13).
Guidance precedence is: the user's current instruction, the spec, then this file.

Before releasing, read `docs/releasing.md`. Before recording fixtures, read spec
section 8.3.

## Development workflow

Design first: the brief is its product. Follow any user-wide model assignments
for the current provider; otherwise choose available models by the roles below.
Set each dispatch's model explicitly. Assign design and complex analysis to the
planning role, routine implementation to the implementation role, and
transcription or single-file mechanical fixes to the support role. Credential
handling, the network policy, the local token, the log-field allowlist, and
release workflows need independent adversarial review. Ordinary code needs its
tests, the gates, and independent code review. Agents assigned design or review
must not implement the same slice; state that restriction in each brief.

Parallel tasks need fixed interfaces, named files with no overlapping ownership,
and a separate git worktree for each worker that edits files. A slice needing a
test alongside another's creates a new file instead of editing a shared one.
Assign one directive per agent; do not add work to a running agent because it
owns the files. Review each task before dependent work starts.

## Architecture rules

Dependency direction is one way:
```
kiro-trust (bin)  →  kiro-trust-kiro  →  kiro-trust-net, kiro-trust-protocol
                  →  kiro-trust-auth  →  kiro-trust-net
```
- `reqwest` appears in `kiro-trust-net` only. Never build an HTTP client
  anywhere else, tests included; test doubles implement the `Upstream` trait.
- `kiro-trust-protocol` has no `tokio`, `reqwest`, or `rusqlite`. Translation
  functions are pure: bytes or structs in, structs out.
- Hosts are named by `Destination` only. Never add a `Url`, a string host, or a
  base-URL override to a public API; `test-endpoints` is the one exception and
  the binary never enables it.
- Regions go through the `Region` and `RuntimeRegion` constructors. Never
  interpolate a string into a hostname.
- `clap` types never leave the binary crate.
- Release builds and the feature check select `-p kiro-trust` alone. A
  workspace-wide build unifies the tests crate's features into the binary.

## Security contracts

- Never log a body, header value, prompt, tool name, tool argument, tool result,
  thinking text, conversation id, ARN, account id, token, or secret. Log only
  the fields in spec 6.4. There is no body-logging flag; do not add one. Payload
  capture exists only behind the `capture` feature.
- Secrets are `secrecy::SecretString`. Call `expose_secret()` only inside
  `TokenSource::with_token`, the OIDC refresh request builder,
  `server::require_token`, `token::write_temp_file`, and `env_cmd::run` (the
  fifth site: `env`'s whole purpose is printing the token, spec 4.3, so there
  is no way to implement it without one; the token goes to stdout only, never
  to a log, stderr, or any error path). Never derive `Serialize`, or a `Debug`
  that prints content, for a type holding one.
- The Kiro database is opened only through `open_read_only`. Never add another
  constructor, never write, never copy the file, never read a table other than
  `auth_kv` and `state`.
- Loopback only. Never add a non-loopback bind override.
- No telemetry, exporter, crash reporter, update check, or model discovery,
  even behind a flag.
- Unknown model returns 400. Never fall back to a default model.
- `x-amzn-codewhisperer-optout` defaults to `true`; `--share-content` is the
  only way to send `false`, and audit shows it.
- Text frames are incremental. Never add overlap removal or dedup between
  frames (kirocc v0.11.1, issue #116).

## Credentials on this machine

A real Identity Center credential lives at
`~/.local/share/kiro-cli/data.sqlite3` (copied from the owner's Mac on
2026-09-08, SSO region ap-southeast-1, runtime region us-east-1). Live tests
may read it without asking.

- Never print, copy, move, or modify it. Ad-hoc queries read key names and
  non-secret fields (expiry, region) only, never a `value` column whole.
- The profile ARN carries an AWS account id. Keep it out of fixtures, docs,
  logs, commits, and chat output.
- Fixtures are public. Record only marker prompts, scrub with
  `cargo xtask scrub`, and keep `scripts/check-fixtures.sh` green. Never
  hand-edit a captured fixture to make a test pass; re-capture and re-scrub.
- No `.env` exists in this project. The proxy reads only `KIRO_TRUST_*`
  variables.

## kirocc reference

`d-kuro/kirocc` v0.11.1 is the behavioral oracle. Clone it into the session
scratchpad when needed; never vendor it into this repository.

- Transcribe a rule only from the files the spec names ("transcribe from
  kirocc ..."), record the rule in the spec, and list the file in `NOTICE`.
- Never port the advisor, tool search, OpenTelemetry, model discovery, social
  login, or API-key paths.
- Transcribed regression cases name the source test in the fixture's
  `meta.json`.

## Testing

```bash
cargo test --workspace                                   # offline: unit, fixture, security
KIRO_TRUST_LIVE=1 cargo test --workspace -- --ignored --test-threads=1   # live, this laptop
cargo fmt --all --check                                  # the CI gate, alongside:
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo deny check advisories bans licenses sources
./scripts/check-packages.sh && ./scripts/check-fixtures.sh && ./scripts/check-features.sh
cargo +nightly fuzz run frame_decode -- -max_total_time=60
cargo publish --workspace --dry-run --locked             # release preflight, no upload
```

Cap the offline suite with `cargo test -- --test-threads=6` on the dev machine
(8 cores). Do not commit `RUST_TEST_THREADS` to `.cargo/config.toml`. Live tests
assert structure, never model wording, and print counts and durations only.
The live command above still skips `forced_refresh_succeeds`: that test forces
a real OIDC refresh and needs a second, explicit `KIRO_TRUST_LIVE_REFRESH=1`
alongside `KIRO_TRUST_LIVE=1` (spec 8.6).

## Release

**A release ends at the signed tag and the GitHub Release assets** (binaries,
SHA-256 sums, attestations, SBOMs). Publishing to crates.io needs the owner's
explicit approval for that version; approval never carries forward. Ask
separately and complete the release meanwhile. Publish only through
`.github/workflows/publish-crates.yml` with the released tag and `crates-io`
environment approval, never locally or crate by crate. Versions can be yanked,
never deleted.

Every workflow pins actions by commit SHA. When Dependabot bumps an action,
keep the SHA form and update the version comment. `cargo-dist` installs as
`dist`, not `cargo dist`; `dist build --artifacts=host` builds the host only.
Tags are `git tag -s`; commits are SSH-signed by the global git config.

## Git

Track `CLAUDE.md` using the existing `.gitignore` negation. This overrides the
global ignore default. There is no `AGENTS.md` in this repository. Default
branch is `master`. Never commit `*.sqlite3` except the synthetic
`tests/fixtures/db/idc.sqlite3`. Durable rules belong in `CONTRIBUTING.md` or
the spec.

# kiro-trust

**Security-first local trust proxy for using Claude Code with Kiro and AWS IAM
Identity Center credentials.**

`kiro-trust` sits between Claude Code and the Kiro runtime:

```text
Claude Code
    │  Anthropic Messages API, loopback, local token
    ▼
kiro-trust
    │  read-only Kiro CLI credential, AWS OIDC refresh
    │  Anthropic ↔ Kiro protocol translation
    ▼
runtime.<region>.kiro.dev
```

It is the only process that holds the Kiro bearer token. Claude Code receives a
separate local token that is useless outside this machine.

## Install

Download the archive for your platform from
[GitHub Releases](https://github.com/dannyota/kiro-trust/releases), then
verify it before running:

```sh
gh attestation verify kiro-trust-x86_64-unknown-linux-gnu.tar.xz --owner dannyota
sha256sum -c kiro-trust-x86_64-unknown-linux-gnu.tar.xz.sha256
```

Put the verified binary on your `PATH`. Each release also carries a CycloneDX
SBOM per crate and binaries built with `cargo auditable`; see
[`docs/security.md`](docs/security.md#verifying-a-release) for what else you can
check.

`cargo install kiro-trust --locked` works once a given version has also been
published to crates.io; that publish needs the owner's explicit approval per
release and is not guaranteed to happen for every tag (see
[section 9](docs/specs/kiro-trust-design.md#9-distribution-and-release) of the
design spec). The GitHub release is the one guaranteed artifact for every
version.

## Usage

You need a working [Kiro CLI](https://kiro.dev) login first: `kiro-trust`
reads its Identity Center credential and never performs its own login flow.

```bash
kiro-trust serve
```

`serve` blocks the terminal, so run the rest in a second shell:

```bash
kiro-trust exec -- claude
```

Or, if you would rather set the variables in the shell itself:

```bash
eval "$(kiro-trust env)"
claude
```

Prefer `exec` where it fits: it puts the token in one child process's
environment and nowhere else, while `eval` puts it in the shell and every
process started from it afterwards.

`kiro-trust serve` reads the Kiro CLI credential read-only, refreshes it
through AWS OIDC when it is near expiry, and listens on loopback with a
freshly generated local token. `kiro-trust exec` and `kiro-trust env` both
supply the `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` Claude Code needs to
talk to it: `exec` sets them on one child process, `env` prints them for `eval`
to put in the current shell. See
[section 4](docs/specs/kiro-trust-design.md#4-command-surface) of the design
spec for every flag and environment variable.

## Guarantees

- The Kiro CLI credential database is opened read-only, and only the
  Identity Center rows are read.
- Outbound traffic goes to `oidc.<region>.amazonaws.com` and
  `runtime.<region>.kiro.dev` only. Redirects fail. Proxy environment
  variables are ignored.
- The listener binds to loopback only, and every request needs the local
  token.
- Request and response bodies are never logged, and no flag exists to log
  them.
- No telemetry, no update checks, no dynamic model discovery.
- No developer-only feature, such as `capture` (which writes real prompts
  and responses to disk), is compiled into a release build.

[`docs/security.md`](docs/security.md) says how each of these is checked, and
which of them `kiro-trust audit` measures rather than states.
[`docs/threat-model.md`](docs/threat-model.md) names the threat each one
answers.

## Audit

```bash
kiro-trust audit [--json]
```

Prints the effective security configuration: listener address, connection
limits, credential database path, outbound hosts, TLS roots, any extra trust
anchor configured with `--extra-ca`, and whether any developer-only feature is
compiled into this build. It never starts a listener and never makes a network
request.

It exits 1 when the listener address cannot be parsed or is not loopback, an
invalid `--runtime-region` is given, the credential database cannot be
confirmed read-only, the credential cannot be read, or a developer-only feature
is compiled in (spec 4.2).

Some printed lines are measurements of the running build and others are fixed
text asserting that a category of code does not exist. The difference matters
when you are relying on `audit` as evidence:
[`docs/security.md`](docs/security.md#what-audit-measures) draws that line
for each printed field.

## Limitations

Each item below is a deliberate decision rather than an omission;
[section 1](docs/specs/kiro-trust-design.md#1-scope) of the design spec has the
reasoning, and section 13 has the backlog.

- Identity Center credentials only: no social login, no Kiro API keys
  (`ksk_…`).
- Claude models only, from a static catalog: no GPT models on Kiro, no
  dynamic model discovery.
- Nothing emulated proxy-side: no Tool Search, Advisor, truncation notice
  injection, or retry of thinking-only responses.
- One local user: no web UI, remote listener, multi-user, or account pooling.
- No telemetry, crash reporting, or update checks, by contract rather than by
  default.
- No plugin system, arbitrary upstream URL, or generic OpenAI gateway.
- No config file, log rotation, CORS, Homebrew tap, background service, or
  HTTP proxy support.

**Refresh token rotation is not fully in kiro-trust's control.** AWS's
`CreateToken` reference does not document whether Identity Center invalidates
a refresh token when it issues a new one. If it does, a refresh performed by
kiro-trust leaves the Kiro CLI's own stored refresh token stale, and you would
have to log in to Kiro CLI again to restore it. kiro-trust cannot persist the
rotated token itself, because the credential database is opened read-only by
design. In ordinary use this is unlikely to matter: kiro-trust refreshes only
when the cached credential is within its validity buffer of expiry (5 minutes
by default), so the Kiro CLI usually refreshes first on its own schedule and
kiro-trust reads the result it already wrote. See
[section 12](docs/specs/kiro-trust-design.md#12-risks) of the design spec for
the full risk register.

## Docs

| Document | What it covers |
| --- | --- |
| [`docs/specs/kiro-trust-design.md`](docs/specs/kiro-trust-design.md) | Scope, architecture, security contracts, verified protocol facts. The source of truth: when code and spec disagree, the spec wins. |
| [`docs/security.md`](docs/security.md) | The guarantees, what `audit` measures, how to verify a release, how to report a vulnerability. |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, threats, and the test or contract behind each mitigation. |
| [`CHANGELOG.md`](CHANGELOG.md) | What changed in each release. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Setup, the CI gates, and what review will hold you to. |
| [`docs/releasing.md`](docs/releasing.md) | Maintainer release procedure. |

## Reference implementation

Protocol behavior follows [d-kuro/kirocc](https://github.com/d-kuro/kirocc),
used as a test oracle. See `NOTICE` for attribution.

## License

Apache-2.0.

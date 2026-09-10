# kiro-trust

**Security-first local trust proxy for using Claude Code with Kiro and AWS IAM
Identity Center credentials.**

See [`docs/specs/kiro-trust-design.md`](docs/specs/kiro-trust-design.md) for
scope, architecture, and the security contracts this proxy holds itself to.

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

Each release also carries a CycloneDX SBOM per crate and binaries built with
`cargo auditable`, so `cargo audit bin` can inspect what actually shipped. Put
the verified binary on your `PATH`.

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
- `kiro-trust audit` prints the effective configuration, and checks three
  of these guarantees that a running build can check for itself (see
  Audit below).

## Audit

```bash
kiro-trust audit [--json]
```

Prints the effective security configuration: listener address, connection
limits, credential database path, outbound hosts, TLS roots, any extra trust
anchor configured with `--extra-ca`, and whether any developer-only
feature (such as `capture`, which writes real prompts and responses to disk)
is compiled into this build. It exits 1 when the listener address cannot be
parsed or is not loopback, an invalid `--runtime-region` is given, the
credential database cannot be confirmed read-only, the credential cannot be
read, or a developer-only feature is compiled in (spec 4.2); it never starts
a listener or makes a network request itself.

Only some of the lines above are measurements of this running build: the
listener address, credential database path and mode, and outbound hosts are
read back from the code that actually enforces them. TLS roots, HTTP proxy
setting, and redirect policy are not read back from anything: they are
`pub const` strings declared next to the `Client` builder calls that set
that behavior (`crates/kiro-trust-net/src/client.rs`), so a change to the
builder would not fail any test tied to these three printed lines. The
behavior itself is pinned by the named tests `oidc_redirect_rejected`,
`runtime_redirect_rejected`, and `proxy_env_ignored`
(`crates/kiro-trust-tests/tests/security_net.rs`), not by `audit`. The
`Telemetry`, `Request body logging`, `Dynamic model discovery`, and
`Automatic updates` lines are fixed text too, printed the same way
regardless of build or configuration, because they each assert that a whole
category of code does not exist in this binary; no field you can print
proves an absence better than the source itself does. Read those four as a
pointer to go verify the claim in the source (or `NOTICE`), not as
something `audit` checked for you.

## Limitations

Out of scope for v0.1, each a deliberate decision rather than an omission
(section 1 of the design spec has the full reasoning):

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

**Refresh token rotation is not fully in kiro-trust's control.** AWS's
`CreateToken` reference does not document whether Identity Center invalidates
a refresh token when it issues a new one. If it does, a refresh performed by
kiro-trust leaves the Kiro CLI's own stored refresh token stale, and you would
have to log in to Kiro CLI again to restore it. kiro-trust cannot fix this by
persisting the rotated token itself: the Kiro CLI credential database is
opened read-only by design (see Guarantees above), so a refreshed token never
leaves kiro-trust's memory and is discarded when it exits. In ordinary use
this is unlikely to matter: kiro-trust only refreshes when the cached
credential is within its validity buffer of expiry (5 minutes by default), so
the Kiro CLI itself usually refreshes first, on its own schedule, and
kiro-trust just reads the result it already wrote. See
[section 12](docs/specs/kiro-trust-design.md#12-risks) of the design spec for
the full risk register.

## Reference implementation

Protocol behavior follows [d-kuro/kirocc](https://github.com/d-kuro/kirocc),
used as a test oracle. See `NOTICE` for attribution.

## License

Apache-2.0.

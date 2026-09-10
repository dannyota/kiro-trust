# Security

What kiro-trust promises, how to check it, and how to report a problem.

## Promises

Every item is a contract in `docs/specs/kiro-trust-design.md` section 6 with
a test behind it.

- Read-only Kiro credential access; only the Identity Center rows are read.
- Two outbound hosts, constructed internally from validated regions. No
  redirects, no proxy, compiled-in TLS roots.
- Loopback listener with a mandatory local token.
- No request or response body logging, and no option to enable it.
- No telemetry, crash reporting, update checks, or model discovery.
- No developer-only feature, such as `capture` (which writes real prompts
  and responses to disk), compiled into a release build.

## What `audit` measures

```sh
kiro-trust audit [--json]
```

`kiro-trust audit` prints the effective security configuration: listener
address, connection limits, credential database path, outbound hosts, TLS
roots, any extra trust anchor configured with `--extra-ca`, and whether any
developer-only feature is compiled into this build. It never starts a listener
and never makes a network request. It exits 1 when the listener address cannot
be parsed or is not loopback, an invalid `--runtime-region` is given, the
credential database cannot be confirmed read-only, the credential cannot be
read, or a developer-only feature is compiled in (spec 4.2).

That exit code checks three of the promises above: read-only credential
access, the loopback listener, and no developer-only feature compiled in. The
printed lines fall into three kinds, and only the first is a measurement.

**Read back from the enforcing code.** The listener address, the credential
database path and mode, and the outbound hosts come from the same code that
enforces them, so these lines change when the behavior changes.

**Constants declared beside the behavior.** TLS roots, the HTTP proxy setting,
and the redirect policy are `pub const` strings declared next to the `Client`
builder calls that set that behavior
(`crates/kiro-trust-net/src/client.rs`). A change to the builder would not
fail any test tied to these three printed lines. The behavior itself is pinned
by the named tests `oidc_redirect_rejected`, `runtime_redirect_rejected`, and
`proxy_env_ignored` (`crates/kiro-trust-tests/tests/security_net.rs`), not by
`audit`.

**Fixed text asserting an absence.** The `Telemetry`, `Request body logging`,
`Dynamic model discovery`, and `Automatic updates` lines print the same way
regardless of build or configuration, because each asserts that a whole
category of code does not exist in this binary. No field a program can print
proves an absence better than the source does. Read those four as a pointer to
verify the claim in the source (or `NOTICE`), not as something `audit` checked
for you. The same holds for the no-body-logging promise above.

## Verifying a release

```sh
gh attestation verify kiro-trust-<target>.tar.xz --owner dannyota
sha256sum -c kiro-trust-<target>.tar.xz.sha256
```

Each release also carries a CycloneDX SBOM per package, and the binaries
embed their dependency list for `cargo audit bin`.

## Reporting

Report vulnerabilities privately through GitHub security advisories on
`dannyota/kiro-trust`. Do not open a public issue for a credential or
content-leak problem.

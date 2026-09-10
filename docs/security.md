# Security

What kiro-trust promises, how to check it, and how to report a problem.

## Promises

Every item is a contract in `docs/specs/kiro-trust-design.md` section 6 with
a test behind it.

- Read-only Kiro credential access; only the Identity Center rows are read.
- OIDC, runtime, and explicit fixed catalog hosts are constructed internally
  from validated regions. No redirects, proxy, or native roots.
- Loopback listener with a mandatory local token.
- No request or response body logging, and no option to enable it.
- No telemetry, crash reporting, or update checks. Explicit `models discover`
  uses only the fixed, bounded catalog operation and never changes routing.
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
`Serve outbound` lists the configured OIDC and runtime hosts. `Manual
discovery outbound` lists the catalog hosts enabled by the same compiled
region policy that discovery uses.

**Constants declared beside the behavior.** TLS roots, the HTTP proxy setting,
and the redirect policy are `pub const` strings declared next to the `Client`
builder calls that set that behavior
(`crates/kiro-trust-net/src/client.rs`). A change to the builder would not
fail any test tied to these three printed lines. The behavior itself is pinned
by the named tests `oidc_redirect_rejected`, `runtime_redirect_rejected`, and
`proxy_env_ignored` (`crates/kiro-trust-tests/tests/security_net.rs`), not by
`audit`.

**Fixed policy text.** `Telemetry`, `Request body logging`, and `Automatic
updates` describe excluded behavior. `Dynamic model discovery` states
`automatic disabled; manual command only`. Those strings describe the source
contract; printing them does not test that every call path obeys it.

Manual discovery can refresh an expired access token through the ordinary
OIDC path. It shares one token source across all pages and never forces a
refresh after a catalog 401 or 403. Each command still owns a separate
in-memory refresh chain, with the cross-process risk described in spec 12.

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

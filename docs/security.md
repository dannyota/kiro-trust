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

Run `kiro-trust audit` to see the effective configuration. It exits non-zero
when a promise does not hold for the running build.

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

# Threat model

Two assets: the AWS/Kiro credential, and the content Claude Code sends
(source code, prompts, tool output). Each threat below names the mitigation
and the test or contract that proves it. Section numbers refer to
`docs/specs/kiro-trust-design.md`.

| Threat | Mitigation | Proof |
| --- | --- | --- |
| A local application uses the proxy to spend the Kiro credential | loopback bind, mandatory local token, constant-time compare, 0600 token file | spec 6.3, security tests `missing_token_401`, `non_loopback_bind_fails` |
| Credential exfiltration through a redirected or substituted upstream | `Destination` enum is the only host input, strict region pattern and runtime allowlist, HTTPS only, redirects rejected, proxy variables ignored, compiled-in TLS roots | spec 6.2, security tests `oidc_redirect_rejected`, `invalid_region_rejected`, `proxy_env_ignored` |
| Source code leaks through logs or diagnostics | no body logging, no flag for it, no telemetry, capture only in a dev feature that release builds omit and audit flags | spec 6.4, 6.5, log-marker security tests, audit gate |
| The proxy corrupts or leaks Kiro CLI state | read-only open with authorizer, only `auth_kv` and `state` by exact key, refreshed tokens kept in memory | spec 6.1, `open_writable_is_impossible`, `only_auth_tables_are_readable` |
| Supply-chain compromise of a dependency, action, or release | committed lockfile, pinned toolchain, `cargo deny`, actions pinned by SHA, attestations, SBOM, `cargo auditable`, owner-approved crates.io publish | spec 9, CI |
| Malformed upstream data crashes or exploits the parser | Rust memory safety, frame size and accumulation caps, CRC checks, fuzz targets | spec 5.5, 8.5 |
| A stale allowlist or pinned user-agent blocks service | release-driven updates, clear error naming the allowlist | spec 12 |

Out of scope: a compromised user account on the same machine (it can read the
Kiro database directly), a compromised Kiro CLI, and a malicious Claude Code
build (it holds the content by definition).

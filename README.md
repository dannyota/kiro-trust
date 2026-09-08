# kiro-trust

**Security-first local trust proxy for using Claude Code with Kiro and AWS IAM
Identity Center credentials.**

Status: pre-release. The design is complete; the implementation follows it.
See [`docs/specs/kiro-trust-design.md`](docs/specs/kiro-trust-design.md).

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
- `kiro-trust audit` prints the effective configuration so you can check
  every line above.

## Reference implementation

Protocol behavior follows [d-kuro/kirocc](https://github.com/d-kuro/kirocc),
used as a test oracle. See `NOTICE` for attribution.

## License

Apache-2.0.

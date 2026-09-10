# Test CA certificate

`test-ca.crt` is one self-signed P-256 CA certificate, generated once with
`openssl req -x509 -newkey ec ...`. It holds a public certificate only: there
is no private key here and none was kept, so nothing can be signed with it.

It exists so the `--extra-ca` tests across three crates share one literal
instead of four hand-copied copies that can drift apart. Load it with
`include_str!`, from a relative path, so a rename breaks the build rather than
one test at a time.

The extension is `.crt`, not `.pem`, deliberately: the repository's
`.gitignore` excludes `*.pem` so that a real key or certificate can never be
committed by accident, and this fixture is not a reason to weaken that rule.

Never add a private key to this directory.

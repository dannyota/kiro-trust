#!/usr/bin/env bash
# Fail if a fixture contains credentials, an ARN, an account id, the owner's
# home path, or a real Kiro hostname. Fixtures are public (spec 8.3).
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=tests/fixtures
[ -d "$DIR" ] || { echo "no $DIR to scan"; exit 0; }

fail=0
report() { echo "LEAK: $1"; shift; printf '  %s\n' "$@"; fail=1; }

# Bearer tokens, Identity Center access tokens (aoa...), JWT-shaped strings,
# refresh tokens, client secrets.
if hits=$(grep -rnaE 'Bearer [A-Za-z0-9._-]{20,}|aoa[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|"(refresh_?[Tt]oken|client_?[Ss]ecret)"\s*:\s*"[^"]{8,}"' "$DIR" 2>/dev/null); then
  report "credential material in a fixture" "$hits"
fi

# A real profile ARN or account id. The scrubber writes the fixture ARN.
if hits=$(grep -rnaE 'arn:aws:codewhisperer:[a-z0-9-]+:[0-9]{12}:' "$DIR" 2>/dev/null | grep -v ':000000000000:profile/FIXTURE'); then
  report "a profile ARN in a fixture" "$hits"
fi
if hits=$(grep -rnaE '(^|[^0-9])[0-9]{12}([^0-9]|$)' "$DIR" 2>/dev/null | grep -v '000000000000'); then
  report "a 12-digit account id in a fixture" "$hits"
fi

# The recording machine's home directory and hostname.
if hits=$(grep -rnaE '/home/[a-z]+/|/Users/[A-Za-z]+/' "$DIR" 2>/dev/null | grep -v '/home/user/'); then
  report "a home path in a fixture" "$hits"
fi

# A Kiro or AWS hostname other than the fixture region.
if hits=$(grep -rnaE '(runtime|management)\.[a-z0-9-]+\.kiro\.dev|oidc\.[a-z0-9-]+\.amazonaws\.com' "$DIR" 2>/dev/null | grep -vE '\.us-east-1\.kiro\.dev|oidc\.us-east-1\.amazonaws\.com'); then
  report "a real hostname in a fixture" "$hits"
fi

# Credentials embedded in a URL authority.
if hits=$(grep -rnaE '://[^/"[:space:]]+:[^/@"[:space:]]+@' "$DIR" 2>/dev/null); then
  report "userinfo in a URL" "$hits"
fi

if [ "$fail" -eq 0 ]; then echo "fixtures clean"; fi
exit "$fail"

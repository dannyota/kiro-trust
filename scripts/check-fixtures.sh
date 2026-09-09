#!/usr/bin/env bash
# Fail if a fixture contains credentials, an ARN, an account id, the owner's
# home path, or a real Kiro hostname. Fixtures are public (spec 8.3).
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=tests/fixtures
[ -d "$DIR" ] || { echo "no $DIR to scan"; exit 0; }

fail=0
report() { echo "LEAK: $1"; shift; printf '  %s\n' "$@"; fail=1; }

# Bearer tokens, Identity Center access tokens (aoa...) and refresh tokens
# (aor...), JWT-shaped strings, client secrets.
if hits=$(grep -rnaE 'Bearer [A-Za-z0-9._-]{20,}|ao[ar][A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|"(refresh_?[Tt]oken|client_?[Ss]ecret)"\s*:\s*"[^"]{8,}"' "$DIR" 2>/dev/null); then
  report "credential material in a fixture" "$hits"
fi

# A real profile ARN or account id. The scrubber writes the fixture ARN. -o
# isolates each match so one allow-listed fixture ARN or id on a line (or,
# with -a, a whole SQLite page treated as one line) cannot mask a different
# real match on the same line.
#
# The allow-listed values below are two more copies of the same constants
# (task-21-fix-1 Minor 6): xtask/src/main.rs's FIXTURE_ARN/
# FIXTURE_CONVERSATION_ID and crates/kiro-trust-tests/src/lib.rs's copies.
# xtask must not depend on kiro-trust-tests, so all three are kept in sync
# by hand; a drift here would make the scrubber emit an ARN or id this
# scanner treats as real.
if hits=$(grep -rnaoE 'arn:aws:codewhisperer:[a-z0-9-]+:[0-9]{12}:profile/[A-Za-z0-9]+' "$DIR" 2>/dev/null | grep -v ':000000000000:profile/FIXTURE'); then
  report "a profile ARN in a fixture" "$hits"
fi
if hits=$(grep -rnaoE '(^|[^0-9])[0-9]{12}([^0-9]|$)' "$DIR" 2>/dev/null | grep -v '000000000000'); then
  report "a 12-digit account id in a fixture" "$hits"
fi

# The recording machine's home directory and hostname.
if hits=$(grep -rnaoE '/home/[A-Za-z0-9._-]+/|/Users/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[^\\]+\\' "$DIR" 2>/dev/null | grep -v '/home/user/'); then
  report "a home path in a fixture" "$hits"
fi

# A Kiro or AWS hostname other than the fixture region.
if hits=$(grep -rnaoE '(runtime|management)\.[a-z0-9-]+\.kiro\.dev|oidc\.[a-z0-9-]+\.amazonaws\.com' "$DIR" 2>/dev/null | grep -vE '\.us-east-1\.kiro\.dev|oidc\.us-east-1\.amazonaws\.com'); then
  report "a real hostname in a fixture" "$hits"
fi

# Credentials embedded in a URL authority.
if hits=$(grep -rnaE '://[^/"[:space:]]+:[^/@"[:space:]]+@' "$DIR" 2>/dev/null); then
  report "userinfo in a URL" "$hits"
fi

if [ "$fail" -eq 0 ]; then echo "fixtures clean"; fi
exit "$fail"

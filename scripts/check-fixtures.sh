#!/usr/bin/env bash
# Fail if a fixture contains credentials, an ARN, an account id, the owner's
# home path, a real Kiro hostname, an email address, or (when
# FIXTURE_SCRUB_NAME names one) the operator's personal name. Fixtures are
# public (spec 8.3).
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=tests/fixtures

# Home-path rule (final-fix-2.md Important 2): a trailing separator used to
# be mandatory on all three platform shapes, so a Unix, macOS, or Windows
# home path at the very end of a string (no trailing separator, the shape of
# `envState.currentWorkingDirectory` for a session run in the home
# directory) matched none of them. The separator is now optional
# (`/?` / `\\?`) on all three, and the Windows segment's character class is
# bounded to stop before a quote or whitespace the same way the Unix/macOS
# classes already do (it used to run to the next backslash or end of line,
# which was harmless only because a trailing backslash was mandatory).
# Widening what gets caught this way cannot drop anything the old rule
# caught. Kept in one variable, shared with the self-test below and the real
# scan, so the two can never drift apart.
HOME_PATH_RE='/home/[A-Za-z0-9._-]+/?|/Users/[A-Za-z0-9._-]+/?|[A-Za-z]:\\Users\\[^\\"[:space:]]+\\?'
# Excludes only an exact `/home/user` or `/home/user/` match (anchored to the
# end of the `-o` output line, which is the end of the matched text): a
# sibling like `/home/user2` or `/home/username` is a different, real value
# and must still be flagged, matching the reasoning in
# `crates/kiro-trust/src/audit.rs`'s home-path abbreviation comment.
HOME_PATH_ALLOW_RE='/home/user/?$'

fail=0
report() { echo "LEAK: $1"; shift; printf '  %s\n' "$@"; fail=1; }

# Self-test (final-fix-2.md Important 2): proves the home-path rule catches
# a path with no trailing separator (end of line, before a quote, or before
# whitespace) on all three platform shapes, still catches one followed by
# more path components, and still leaves the fixture's own `/home/user`
# placeholder (and a real sibling like `/home/user2`) alone or flagged as
# appropriate. Runs before the real scan so a broken rule fails loud instead
# of silently scanning with one.
self_test_home_path() {
  local tmp
  tmp=$(mktemp -d)
  cat >"$tmp/case.txt" <<'CASES'
"cwd": "/home/alice"
free text /home/alice here
ends at eol /home/alice
"cwd": "/home/alice/project/file.go"
"cwd": "/Users/alice"
"cwd": "/Users/alice/project"
"cwd": "C:\Users\alice"
"cwd": "C:\Users\alice\project"
"cwd": "/home/user"
"cwd": "/home/user/project"
"cwd": "/home/user2"
CASES
  local hits n want=9
  hits=$(grep -rnaoE "$HOME_PATH_RE" "$tmp" 2>/dev/null | grep -vE "$HOME_PATH_ALLOW_RE" || true)
  n=$(grep -c . <<<"$hits" || true)
  rm -rf "$tmp"
  if [ "$n" -ne "$want" ]; then
    echo "self-test failed: home-path rule matched $n leaks, want $want" >&2
    printf '%s\n' "$hits" >&2
    exit 1
  fi
}
self_test_home_path

# Self-test runs unconditionally above, regardless of whether $DIR exists
# yet, so a broken rule is caught even before there is anything to scan.
[ -d "$DIR" ] || { echo "no $DIR to scan"; exit 0; }

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
if hits=$(grep -rnaoE "$HOME_PATH_RE" "$DIR" 2>/dev/null | grep -vE "$HOME_PATH_ALLOW_RE"); then
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

# An email address (final-fix-2.md Important 3): the request body Claude
# Code sends carries context beyond the operator's prompt, and the git
# author name and email could reach it; neither the scrubber nor this
# scanner had a rule for either. This one needs no operator input, unlike
# the name rule below, because an email address has a recognizable shape the
# way a home path or hostname does.
if hits=$(grep -rnaoE '[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$DIR" 2>/dev/null); then
  report "an email address in a fixture" "$hits"
fi

# The operator's personal name (final-fix-2.md Important 3): unlike a home
# path, a hostname, or an email address, a name has no recognizable shape,
# so this scanner can only check for one when told what it is. Set
# FIXTURE_SCRUB_NAME to the same value passed to `cargo xtask scrub --name`
# (spec 8.3); an operator who recorded a fixture without passing `--name`
# gets no coverage here either, which is exactly why `--name` is documented
# as required for a capture that reaches this scanner.
if [ -n "${FIXTURE_SCRUB_NAME:-}" ]; then
  if hits=$(grep -rnaoE "\\b${FIXTURE_SCRUB_NAME}\\b" "$DIR" 2>/dev/null); then
    report "the operator's name in a fixture" "$hits"
  fi
fi

if [ "$fail" -eq 0 ]; then echo "fixtures clean"; fi
exit "$fail"

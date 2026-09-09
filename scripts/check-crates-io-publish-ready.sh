#!/usr/bin/env bash
set -euo pipefail

api_root=https://crates.io/api/v1
expected_user=dannyota
crates=(kiro-trust-protocol kiro-trust-net kiro-trust-auth kiro-trust-kiro kiro-trust)
user_agent='kiro-trust-publish-preflight (https://github.com/dannyota/kiro-trust)'

if (( $# != 0 )); then
  printf '%s\n' 'crates.io publishing readiness guard accepts no arguments' >&2
  exit 1
fi

if ! tmpdir=$(mktemp -d 2>/dev/null); then
  printf '%s\n' 'could not create private directory for crates.io readiness check' >&2
  exit 1
fi
trap 'rm -rf -- "$tmpdir" >/dev/null 2>&1 || true' EXIT

if curl_version=$(curl --disable --version 2>/dev/null); then
  :
else
  printf '%s\n' 'curl 8.4.0 or newer is required for crates.io readiness checks' >&2
  exit 1
fi
if [[ ! "$curl_version" =~ ^curl[[:space:]]+([0-9]+)\.([0-9]+)\.([0-9]+)([[:space:]]|$) ]]; then
  printf '%s\n' 'curl 8.4.0 or newer is required for crates.io readiness checks' >&2
  exit 1
fi
curl_major=${BASH_REMATCH[1]}
curl_minor=${BASH_REMATCH[2]}
curl_patch=${BASH_REMATCH[3]}
if (( 10#$curl_major < 8 || (10#$curl_major == 8 && 10#$curl_minor < 4) )); then
  printf '%s\n' 'curl 8.4.0 or newer is required for crates.io readiness checks' >&2
  exit 1
fi

check_owner() {
  local crate=$1
  local response="$tmpdir/$crate.json"
  local status
  local curl_status

  if status=$(curl --disable --proto =https --tlsv1.2 --connect-timeout 5 --max-time 15 \
    --max-filesize 1048576 --user-agent "$user_agent" --output "$response" \
    --write-out '%{http_code}' "$api_root/crates/$crate/owners" 2>/dev/null); then
    :
  else
    curl_status=$?
    if (( curl_status == 63 )); then
      printf '%s\n' "$crate owner response exceeds the 1 MiB limit" >&2
    else
      printf '%s\n' "$crate owner request failed" >&2
    fi
    return 1
  fi

  if [[ "$status" == 404 ]]; then
    printf '%s\n' "$crate is not registered; the normal Trusted Publishing workflow cannot perform a crate's first publication and a separate owner policy decision is required" >&2
    return 1
  fi
  if [[ "$status" != 200 ]]; then
    printf '%s\n' "$crate owner request returned an unexpected HTTP status" >&2
    return 1
  fi
  if ! python3 - "$response" "$expected_user" 2>/dev/null <<'PY'
import json
import sys

def reject_non_finite(_constant):
    raise ValueError

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        payload = json.load(handle, parse_constant=reject_non_finite)
except (OSError, UnicodeError, ValueError, RecursionError):
    raise SystemExit(1)

users = payload.get("users") if isinstance(payload, dict) else None
if not isinstance(users, list):
    raise SystemExit(1)
if not any(
    isinstance(user, dict)
    and user.get("kind") == "user"
    and user.get("login") == sys.argv[2]
    for user in users
):
    raise SystemExit(1)
PY
  then
    printf '%s\n' "$crate owner response does not list the expected user" >&2
    return 1
  fi
}

for crate in "${crates[@]}"; do
  check_owner "$crate"
done

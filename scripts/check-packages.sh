#!/usr/bin/env bash
# Every crate version equals the workspace version, and each published
# package contains only what it should. Python 3.11+ for tomllib.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

python3 - <<'PY'
import sys, tomllib
with open("Cargo.toml", "rb") as f:
    root = tomllib.load(f)
want = root["workspace"]["package"]["version"]
wrong = []
for name in ("kiro-trust-protocol", "kiro-trust-net", "kiro-trust-auth", "kiro-trust-kiro", "kiro-trust"):
    dep = root["workspace"]["dependencies"][name]["version"]
    if dep != want:
        wrong.append(f"workspace dependency {name} = {dep}")
    with open(f"crates/{name}/Cargo.toml", "rb") as f:
        pkg = tomllib.load(f)["package"]
    v = pkg["version"]
    if v != {"workspace": True} and v != want:
        wrong.append(f"package {name} = {v}")
for w in wrong:
    print(w, "does not match workspace version", want, file=sys.stderr)
sys.exit(1 if wrong else 0)
PY

check_package() {
  local package=$1 entrypoint=$2 files
  files=$(cargo package --package "$package" --list --locked --allow-dirty)
  if grep -Eq '(^|/)tests/fixtures/' <<<"$files"; then
    echo "$package package contains fixture data" >&2
    return 1
  fi
  for required in Cargo.toml Cargo.toml.orig Cargo.lock "$entrypoint"; do
    grep -Fxq "$required" <<<"$files" || { echo "$package package is missing $required" >&2; return 1; }
  done
}

check_package kiro-trust-protocol src/lib.rs
check_package kiro-trust-net src/lib.rs
check_package kiro-trust-auth src/lib.rs
check_package kiro-trust-kiro src/lib.rs
check_package kiro-trust src/main.rs
echo "packages ok"

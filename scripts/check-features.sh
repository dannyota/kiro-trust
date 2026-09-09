#!/usr/bin/env bash
# The binary must carry neither dev feature, and the protocol crate must stay
# free of network, SQLite, and async runtime dependencies (spec 8.4).
set -euo pipefail
cd "$(dirname "$0")/.."

features=$(cargo tree -e features -p kiro-trust --locked 2>/dev/null)
for bad in 'feature "capture"' 'feature "test-endpoints"'; do
  if grep -Fq "$bad" <<<"$features"; then
    echo "kiro-trust binary carries $bad" >&2
    exit 1
  fi
done

tree=$(cargo tree -p kiro-trust-protocol -e normal --locked 2>/dev/null)
for bad in reqwest rusqlite tokio hyper; do
  if grep -Eq "^[^a-z]*$bad v" <<<"$tree"; then
    echo "kiro-trust-protocol depends on $bad" >&2
    exit 1
  fi
done
echo "features ok"

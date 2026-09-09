#!/usr/bin/env bash
# Guard against `crates-io` being auto-created with no protection rules.
# GitHub creates a referenced environment on first use with zero rules, so
# without this check the first `publish-crates.yml` dispatch would publish
# with no owner approval and no restriction on which ref can deploy. Run
# from both the `verify` and `publish` jobs (task-23-fix-1.md Critical).
#
# Requires two rules on the environment, not one:
#   - required_reviewers, with at least one reviewer: without it there is no
#     approval.
#   - a deployment branch policy: `workflow_dispatch` runs the workflow file
#     from the dispatched ref, so a writer could push a branch with the
#     checks removed and dispatch that. Only a branch policy stops a
#     modified workflow from reaching the environment at all. This script
#     only checks that a policy is configured; docs/releasing.md requires
#     the owner to scope it to `master`.
#
# Fails closed: a 404, a non-200, a malformed or non-object response, or
# either rule missing all exit non-zero with a message naming what is
# missing and how to fix it. This is a backstop, not the mechanism: the
# environment's own protection rules are what actually pause the job for
# approval and gate which ref reaches it.
set -euo pipefail

repo=dannyota/kiro-trust
environment=crates-io

if (( $# != 0 )); then
  printf '%s\n' 'crates-io environment guard accepts no arguments' >&2
  exit 1
fi

if ! response="$(gh api "repos/$repo/environments/$environment" 2>&1)"; then
  printf '%s\n' "could not read the '$environment' environment (404 or request failure): $response" >&2
  printf '%s\n' "fix: create the '$environment' environment under Settings > Environments with a required reviewer and a deployment branch policy restricted to master before the first dispatch" >&2
  exit 1
fi

if ! jq -e 'type == "object"' <<<"$response" >/dev/null 2>&1; then
  printf '%s\n' "environment '$environment' guard: response is not a JSON object (malformed or unexpected shape)" >&2
  exit 1
fi

has_reviewers="$(jq '[(.protection_rules // [])[] | select(.type == "required_reviewers") | select(((.reviewers // []) | length) > 0)] | length > 0' <<<"$response")"
has_branch_policy="$(jq '(.deployment_branch_policy // null) != null and ((.deployment_branch_policy.protected_branches == true) or (.deployment_branch_policy.custom_branch_policies == true))' <<<"$response")"

missing=()
if [ "$has_reviewers" != "true" ]; then
  missing+=("a required_reviewers protection rule with at least one reviewer")
fi
if [ "$has_branch_policy" != "true" ]; then
  missing+=("a deployment branch policy restricting which branches or tags may deploy")
fi

if [ "${#missing[@]}" -ne 0 ]; then
  printf '%s\n' "environment '$environment' is missing: ${missing[*]}" >&2
  printf '%s\n' "fix: in Settings > Environments > $environment, add a required reviewer and set 'Deployment branches and tags' to a policy restricted to master" >&2
  exit 1
fi

echo "environment '$environment' has a required reviewer and a deployment branch policy"

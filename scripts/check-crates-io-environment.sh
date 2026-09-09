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
#     modified workflow from reaching the environment at all.
#
# The environment payload's `deployment_branch_policy` carries only two
# booleans, `protected_branches` and `custom_branch_policies`; neither says
# which branch or pattern is actually allowed. `protected_branches` delegates
# to the repository's branch-protection configuration, which no environment
# endpoint exposes, so this script cannot verify it: docs/releasing.md
# requires the owner to hand-check that master is the protected branch.
# `custom_branch_policies`, though, has a sibling endpoint that returns the
# real patterns and is readable with the same access:
#   GET /repos/{owner}/{repo}/environments/{name}/deployment-branch-policies
# A `custom_branch_policies` environment can carry a pattern that restricts
# nothing, such as `{"name": "*", "type": "tag"}` (task-23-fix-2.md
# Important 1), so this script fetches that endpoint and requires every
# entry to be a branch policy naming exactly `master` before treating the
# rule as satisfied.
#
# Fails closed: a 404, a non-200, a malformed or non-object response, a
# custom-policy list that is empty or contains anything but a `master`
# branch policy, a timed-out request, or either top-level rule missing, all
# exit non-zero with a message naming what is missing and how to fix it.
# This is a backstop, not the mechanism: the environment's own protection
# rules are what actually pause the job for approval and gate which ref
# reaches it.
set -euo pipefail

# `GITHUB_REPOSITORY` is set by the Actions runner in every job; the literal
# is a fallback so the script still runs locally and in a fork reads its own
# environment rather than upstream's (task-23-fix-2.md Minor 3).
repo="${GITHUB_REPOSITORY:-dannyota/kiro-trust}"
environment=crates-io
# Bound each network call so a hung request fails fast and legibly instead of
# riding out the job's `timeout-minutes: 30` (task-23-fix-2.md Minor 4).
gh_timeout=15s

if (( $# != 0 )); then
  printf '%s\n' 'crates-io environment guard accepts no arguments' >&2
  exit 1
fi

if ! response="$(timeout "$gh_timeout" gh api "repos/$repo/environments/$environment" 2>&1)"; then
  printf '%s\n' "could not read the '$environment' environment (404, timeout, or request failure): $response" >&2
  printf '%s\n' "fix: create the '$environment' environment under Settings > Environments with a required reviewer and a deployment branch policy restricted to master before the first dispatch" >&2
  exit 1
fi

if ! jq -e 'type == "object"' <<<"$response" >/dev/null 2>&1; then
  printf '%s\n' "environment '$environment' guard: response is not a JSON object (malformed or unexpected shape)" >&2
  exit 1
fi

has_reviewers="$(jq '[(.protection_rules // [])[] | select(.type == "required_reviewers") | select(((.reviewers // []) | length) > 0)] | length > 0' <<<"$response")"
protected_branches="$(jq '(.deployment_branch_policy // null) != null and .deployment_branch_policy.protected_branches == true' <<<"$response")"
custom_branch_policies="$(jq '(.deployment_branch_policy // null) != null and .deployment_branch_policy.custom_branch_policies == true' <<<"$response")"

# Empty until one of the two paths below proves out; the wording it ends up
# with says which path was verified and which was only delegated, so the
# operator knows what was actually proven.
branch_policy_status=""

if [ "$protected_branches" = "true" ]; then
  branch_policy_status="protected_branches delegated to branch-protection settings (not verified by this script; confirm master is the protected branch per docs/releasing.md)"
elif [ "$custom_branch_policies" = "true" ]; then
  if ! policies="$(timeout "$gh_timeout" gh api "repos/$repo/environments/$environment/deployment-branch-policies" 2>&1)"; then
    printf '%s\n' "environment '$environment': could not read deployment branch policies (non-200, timeout, or request failure): $policies" >&2
    exit 1
  fi
  if ! jq -e 'type == "object"' <<<"$policies" >/dev/null 2>&1; then
    printf '%s\n' "environment '$environment': deployment-branch-policies response is not a JSON object (malformed or unexpected shape)" >&2
    exit 1
  fi
  policy_ok="$(jq '(.branch_policies // []) | length > 0 and all(.type == "branch" and .name == "master")' <<<"$policies")"
  if [ "$policy_ok" != "true" ]; then
    printf '%s\n' "environment '$environment': custom_branch_policies is set but no policy restricts deploys to a 'master' branch (found: $(jq -c '[(.branch_policies // [])[] | {name, type}]' <<<"$policies"))" >&2
    printf '%s\n' "fix: in Settings > Environments > $environment > Deployment branches and tags, remove any tag or wildcard policy and add a branch policy naming exactly 'master'" >&2
    exit 1
  fi
  branch_policy_status="custom_branch_policies verified: every entry is a branch policy naming master"
fi

missing=()
if [ "$has_reviewers" != "true" ]; then
  missing+=("a required_reviewers protection rule with at least one reviewer")
fi
if [ -z "$branch_policy_status" ]; then
  missing+=("a deployment branch policy restricting which branches may deploy")
fi

if [ "${#missing[@]}" -ne 0 ]; then
  printf '%s\n' "environment '$environment' is missing: ${missing[*]}" >&2
  printf '%s\n' "fix: in Settings > Environments > $environment, add a required reviewer and set 'Deployment branches and tags' to a policy restricted to master" >&2
  exit 1
fi

echo "environment '$environment' has a required reviewer and a deployment branch policy ($branch_policy_status)"

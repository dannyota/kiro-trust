# Releasing kiro-trust

Maintainer procedure. Users do not need this; see the README to install.

A release builds cross-platform binaries and publishes a GitHub Release. It
does **not** publish to crates.io. Publishing is a separate workflow that runs
only when the owner dispatches it for that version, and most releases never
reach it. Publish to crates.io only through GitHub Actions; never publish
locally.

Publishing to crates.io is a separate, opt-in step that needs the owner's
explicit approval for that specific version. Approval does not carry forward:
0.1.3 being on crates.io is not permission to put 0.1.4 there. The asymmetry is
the reason: a tag and a GitHub Release can be deleted, while a crates.io
version can only be yanked, which hides it from resolution without removing it.
A version withheld today can be published tomorrow; one published today cannot
be withdrawn.

When approval is given, submit all five crates through one workspace command.
Cargo packages and verifies all five before uploading dependency-ready crates.
Uploads are not atomic: a registry rejection or connection failure can leave a
partial version set. The binary depends on the three libraries by version, so
publishing it alone can leave `cargo install kiro-trust` unable to resolve.
`kiro-trust` depends on `kiro-trust-protocol`, `kiro-trust-net`,
`kiro-trust-auth`, and `kiro-trust-kiro`; `kiro-trust-kiro` depends on
`kiro-trust-net` and `kiro-trust-protocol`; `kiro-trust-auth` depends on
`kiro-trust-net`. `xtask` and test support are not published. Publish order is
`kiro-trust-protocol`, `kiro-trust-net`, `kiro-trust-auth`, `kiro-trust-kiro`,
`kiro-trust`, matching that dependency order. See the
[Cargo upload sequence](https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/cargo/ops/registry/publish.rs#L150-L251).

1. Bump the version in `Cargo.toml`: `[workspace.package] version` and the
   `version` fields for `kiro-trust-protocol`, `kiro-trust-net`,
   `kiro-trust-auth`, and `kiro-trust-kiro` in `[workspace.dependencies]`.
   Bumping only `[workspace.package] version` leaves stale requirements in the
   dependency metadata.
2. Regenerate the audit gate fixture: its `"version"` field is not stripped by
   the gate, so a version bump that skips this step fails CI, not silently.

   ```bash
   cargo build --release --locked -p kiro-trust
   ./target/release/kiro-trust audit --json --kiro-db tests/fixtures/db/idc.sqlite3 --token-file /tmp/kiro-trust-audit/token \
     | python3 -c 'import json,sys; d=json.load(sys.stdin); d.pop("commit"); print(json.dumps(d, indent=2, sort_keys=True))' \
     > tests/fixtures/db/idc-audit.json
   ```

3. Add a dated entry to `CHANGELOG.md`.
4. Run `cargo fmt --all --check`. Prefer GitHub Actions for the build and test
   gates below to limit memory use on the development laptop.
5. Push `master` and require CI success for that exact commit.
6. Dispatch `.github/workflows/release-preflight.yml` on `master` and require
   success for that same commit.
7. `git tag -s vX.Y.Z -m "kiro-trust vX.Y.Z" && git push origin vX.Y.Z`. The
   tag triggers `.github/workflows/release.yml`, which builds the binary
   matrix and publishes the GitHub Release with attestations and SBOMs.
8. Confirm the release carries a complete asset list. **The release ends
   here.** A user-facing check for any downloaded per-target archive:

   ```bash
   gh attestation verify kiro-trust-x86_64-unknown-linux-gnu.tar.xz --owner dannyota
   ```

   Attestations cover only the per-target archives. The two installers,
   `source.tar.gz`, `sha256.sum`, and the SBOM (`kiro-trust.cdx.xml`) are not
   attested; verify those with `sha256sum -c` against `sha256.sum` instead.
   This is a deliberate scope, not a gap: the job that builds those global
   artifacts only fetches the already-attested per-target archive and
   derives installers and checksums from it.

9. Only with the owner's explicit approval for this version: dispatch
   `.github/workflows/publish-crates.yml` with the tag and approve the
   `crates-io` environment when the run pauses for review. A `verify` job
   checks out `refs/tags/<tag>`, refuses unless every workspace version field
   equals the tag and the GitHub Release for it carries every expected asset
   (the per-target archives and checksums, the installers, `source.tar.gz`
   and its checksum, `dist-manifest.json`, `sha256.sum`, and
   `kiro-trust.cdx.xml`), checks that all five crate names exist with the
   expected owner, and repeats the dry run. Both `verify` and `publish` also
   require the `crates-io` environment to carry a required-reviewer rule and
   a deployment branch policy, failing closed if either is absent (see
   below); only then does the `publish` job wait for environment approval.
   It repeats the crate ownership check before obtaining a short-lived
   crates.io Trusted Publishing token and submitting the workspace.

CI in step 5 runs, across its `test`, `gates`, `audit`, and `fuzz-check`
jobs: formatting, locked Clippy, locked workspace tests, package-content,
fixture-leak, and feature checks, the audit-command regression check,
`cargo-deny` (advisories, bans, licenses, sources), and a type check of the
fuzz targets. Preflight in step 6 verifies the workspace packages and the
SBOM tool without uploading anything. Both must pass for the exact release
commit before tagging.

For local checks when needed, cap builds at two jobs and tests at four threads.
The package check requires Python 3.11 or later for TOML parsing.
Run one build-heavy command at a time:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --jobs 2 -- -D warnings
cargo test --locked --workspace --jobs 2 -- --test-threads=4
./scripts/check-packages.sh
./scripts/check-fixtures.sh
./scripts/check-features.sh
```

This local list is a fast subset for iterating; `cargo-deny` and the fuzz
matrix are heavier and run in CI, not here.

After step 5 passes CI, dispatch and identify the preflight run:

```bash
release_sha="$(git rev-parse HEAD)"
gh workflow run release-preflight.yml --ref master
gh run list --workflow release-preflight.yml --branch master \
  --event workflow_dispatch --limit 5
```

The listed run's head SHA must equal `release_sha`. Once it appears, capture
that row's numeric database ID in `preflight_run_id`, require the variable to
be nonempty, and run
`gh run watch "$preflight_run_id" --exit-status`. If the run has not appeared
yet, repeat the list command before selecting it.

Step 6 stays in the default path even though step 9 usually does not run. Its
dry run on GitHub Actions catches packaging errors, such as a missing
`include` or a path dependency without a version, while they are still free to
fix. Finding them later, on the day publishing is approved, means fixing them
against a version already tagged and released.

Publish last, because it is the only step that cannot be undone. A tag and a
GitHub Release can be deleted; a crates.io version can only be yanked. Running
the matrix first means a broken build costs a deleted tag rather than a
permanent version, and it makes every release prove itself the way a release
candidate would. The publish workflow enforces that order by refusing a tag
whose Release is missing any asset.

To dispatch and follow the publish run:

```bash
gh workflow run publish-crates.yml --ref master -f tag=vX.Y.Z
gh run list --workflow publish-crates.yml --limit 3
```

Capture the listed run's numeric database ID in `publish_run_id`, require it
to be nonempty, then `gh run watch "$publish_run_id" --exit-status`.

The `publish` job waits in the `crates-io` environment until the owner
approves it in the Actions UI. That gate is repository configuration, not
workflow text: the environment must exist under Settings, Environments, with
**both** the owner as a required reviewer **and** a deployment branch policy
restricting deployments to `master`. Both requirements matter:
`workflow_dispatch` runs the workflow file from whatever ref is dispatched,
so without a branch policy a writer could push a branch with the checks
stripped out and dispatch that; only the branch policy stops a modified
workflow from reaching the environment at all.

GitHub creates a missing environment on first use with no protection rules,
which would let a dispatch publish without approval and from any ref. Both
the `verify` and `publish` jobs run `scripts/check-crates-io-environment.sh`
against `GET /repos/{owner}/{repo}/environments/crates-io` (where
`{owner}/{repo}` is derived from `${GITHUB_REPOSITORY}`, falling back to
`dannyota/kiro-trust` when not set), and when `custom_branch_policies` is
configured, also queries `GET /repos/{owner}/{repo}/environments/crates-io/deployment-branch-policies`
to verify every policy is a branch policy named `master`. The script fails the
job when either the required reviewers rule or a deployment branch policy is
absent, a 404 is returned, or the response is malformed. Treat that script as
a backstop, not the mechanism: it can only fail a run after the fact, while
the environment's own protection rules are what actually pause the job for
approval and restrict which ref can reach it. Confirm both rules before the
first dispatch:

```bash
gh api repos/dannyota/kiro-trust/environments/crates-io \
  --jq '.protection_rules[] | select(.type == "required_reviewers")'
gh api repos/dannyota/kiro-trust/environments/crates-io \
  --jq '.deployment_branch_policy'
```

The second command must show `protected_branches: true` or
`custom_branch_policies: true`; a `custom_branch_policies` policy also needs
its named branch pattern checked separately in Settings, Environments to
confirm it is scoped to `master` and not a wildcard.

Before every dispatch, verify each crate's Trusted Publishing entry on
crates.io: repository owner `dannyota`, repository `kiro-trust`, workflow
`publish-crates.yml`, environment `crates-io`. Check all five entries and the
environment's required-reviewer rule and deployment branch policy. A
successful token exchange does not prove the token authorizes all five
crates.

The normal workflow runs `scripts/check-crates-io-publish-ready.sh` in both
jobs before token exchange or upload. The guard requires all five names to
exist on crates.io with `dannyota` as an owner. A failed registry read also
stops the workflow. The guard does not inspect Trusted Publisher settings and
cannot replace the owner's settings check. Both workspace commands use
`--registry crates-io`. `cargo publish --workspace --dry-run --locked
--registry crates-io` packages, checks, and builds all selected crates without
uploading. It does not prove per-crate registry authorization or Trusted
Publisher configuration.

[Trusted Publishing requires an existing crate](https://crates.io/docs/trusted-publishing).
The first publication of each crate cannot go through Trusted Publishing at
all: crates.io has no crate to attach the publisher configuration to yet.
That first publish needs an explicit, one-time owner decision (a manual
`cargo login` publish, or a short-lived API token) made and revoked outside
this workflow, before Trusted Publishing is configured for that crate.
Verify every crate's ownership and Trusted Publishing entry before dispatch;
the workflow's registry checks confirm ownership but not that Trusted
Publishing is configured.

**That exception was used once and is closed.** Version 0.1.0 of all five
crates was published locally on 2026-09-09 under the owner's explicit
approval, because none of the five existed on crates.io and Trusted
Publishing had nothing to attach to. Trusted Publishing is now configured on
all five (owner `dannyota`, repository `kiro-trust`, workflow
`publish-crates.yml`, environment `crates-io`), and the `crates-io`
environment carries a required reviewer and a branch policy naming `master`.
Every version after 0.1.0 publishes through `publish-crates.yml` and needs
separate approval for that version. Do not publish locally again.

Cross-platform artifacts are built by
[`cargo-dist`](https://opensource.axo.dev/cargo-dist/); the matrix runs in CI.
Prefer the release workflow for builds. If a local host build is needed, use
`CARGO_BUILD_JOBS=2 dist build --artifacts=host`.

## Do not write a credential-shaped URL in the changelog

cargo-dist embeds the changelog entry in the plan manifest. The workflow passes
that manifest between jobs as a job output. The GitHub runner masks anything
resembling a URL credential, the literal `user:password@host` form. If an
output contains masked text, the runner **drops the whole output** with `Skip
output 'val' since it may contain secret`. The build matrix comes from that
output, so every build job silently skips. The release then publishes only a
manifest while reporting success.

Describe such a URL in prose instead. If a release ever produces only
`dist-manifest.json`, look for that warning in the `plan` job first.

## When a release candidate is worth it

Tag an `-rc.N` only when the build matrix is unproven: it has never run, or
`dist-workspace.toml` changed its target list. Check the last release's assets
first:

```bash
gh release view vX.Y.Z --json assets --jq '.assets[].name'
```

A complete asset list means the matrix works, so tag the real version.
Otherwise, tag `-rc.1`, confirm its assets, install from it, then delete the
release and tag before tagging for real.

A release candidate costs a second full matrix build and four cleanup commands.
Once a release has proved an unchanged matrix, repeating that test adds little
protection. Test it again only after the target list changes.

What a candidate no longer has to insure against is the matrix itself, because
step 7 now runs before step 9: the real tag proves the build while both the tag
and the Release are still deletable. What it *can* insure, once a version has
users, is the publish. A crates.io version is permanent: yanking hides it from
resolution but never removes it, and `cargo install kiro-trust` would then
have users to break. When a release changes packaging rather than the target
list, publish a `-rc.N` first through `publish-crates.yml`, with the owner's
approval for that candidate and a complete GitHub Release. Pre-release
versions are ignored by a `^0.1` requirement and by `cargo install` unless
asked for by name, so this tests packaging before the final version is
permanent.

# DevOps

## CI for this repo

`.github/workflows/ci.yml` has two jobs:

1. `check`: `npm ci`, typecheck, lint, tests. Why: every change is proven before it can merge.
2. `dogfood`: runs the local action (`uses: ./`) against this repo with `fail-on: high`. Why: the tool must pass its own policy, and this exercises the action end to end.

Every third-party action is pinned to a full commit SHA with the version in a comment. Why: a moved tag cannot change what CI runs.

## Composite action

`action.yml` sets up Node 22, builds Guard, runs `scripts/install-scanners.sh`, then scans with `--require-tools`. Why `--require-tools`: in CI a missing scanner must fail the build, not silently pass. Inputs are passed through `env:` and never interpolated into the script. Why: this is the same script injection rule Guard enforces.

## Scanner install

See [[ADR-004 Pinned scanner releases]] and [[Update pinned scanner versions]].

## Local machine notes

On the Intel Mac, Homebrew has bottles for hadolint, actionlint, gitleaks and shellcheck, but compiles trivy and osv-scanner from source. That build needs about 9 GB of Go caches. Use the Linux container instead (see [[2026-10-17 Disk filled by Homebrew source build]]).

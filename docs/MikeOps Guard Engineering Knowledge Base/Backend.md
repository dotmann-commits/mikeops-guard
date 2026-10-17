# Backend

The "backend" is the orchestration core and the scanner adapters.

## Process execution

`core/exec.ts` uses `spawn` with an argument array and no shell. It enforces a timeout (SIGKILL) and a 256 MB output cap. `ENOENT` becomes `ToolMissingError`, which the orchestrator reports as skipped with an install hint.

## Adapter contracts

| Adapter | Command | Success exit codes | Severity mapping |
|---|---|---|---|
| hadolint | `hadolint --no-fail --format json <files>` | 0 | error high, warning medium, info low, style info |
| trivy-config | `trivy config --format json --quiet --exit-code 0 .` | 0 | Trivy label |
| actionlint | `actionlint -format '{{json .}}' -no-color <files>` | 0, 1 | credentials high, shellcheck low, others medium |
| gitleaks | `gitleaks git|dir --report-format json --report-path <tmp> --redact --exit-code 0 .` | 0 | always critical |
| osv-scanner | `osv-scanner scan source --recursive --format json .` | 0, 1, 128 | CVSS band of group max severity |
| trivy fs | `trivy fs --scanners vuln --format json --quiet --exit-code 0 .` | 0 | Trivy label |

osv-scanner advisories can mix `ECOSYSTEM`, `SEMVER` and `GIT` ranges. Only the first two are used for the "Upgrade to" version, because `GIT` ranges hold commit hashes. The CVE id is taken from the group ids or aliases when present.

Any other exit code throws `ScannerError` with the last lines of stderr.

## Built-in workflow audit

`scanners/workflow-audit/workflow.ts` parses YAML 1.2 with a line counter, so `on:` stays a string and every finding gets an exact line, including the line inside a `run: |` block. Rules live in `rules/` and share the `WorkflowRule` type.

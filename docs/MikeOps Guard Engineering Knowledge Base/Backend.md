# Backend

The "backend" is the orchestration core and the scanner adapters.

## Process execution

`core/exec.ts` uses `spawn` with an argument array and no shell. It enforces a timeout and a 256 MB output cap. `ENOENT` becomes `ToolMissingError`, which the orchestrator reports as skipped with an install hint.

- **Process groups (since 21 October 2026).** On macOS and Linux each scanner starts detached, as the leader of its own process group. A timeout, output overflow or cancel sends SIGKILL to the whole group, so helpers such as `git` under Gitleaks stop too. Windows has no process groups, so there only the scanner itself is stopped.
- **Cancellation.** `cli/index.ts` installs SIGINT and SIGTERM handlers (`cli/signals.ts`). The first signal aborts one `AbortController`. Its signal reaches every `execCommand` call, the scan context and the Ollama client. `runScan` then throws `CancelledError` instead of building a report, its `finally` removes the temp dir, and `main` exits 130. A second signal exits at once.
- **Bounded file reads.** `core/files.ts` reads at most a byte limit from an open handle (1 MB by default), and `core/concurrency.ts` `mapLimit` keeps at most 32 file reads in flight. Built-in scanners call `ctx.skipFile` for files they could not check. Skipped workflows, SQL, env files and Supabase configs mark the scanner `incomplete`. Oversized JavaScript, nearly always a generated bundle, is listed but does not.

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

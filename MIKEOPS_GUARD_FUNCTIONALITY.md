# MikeOps Guard: functionality

**MikeOps Guard finds exposed secrets, risky GitHub Actions, Dockerfile problems and vulnerable dependencies before you ship.**

- **What it is:** an open-source DevSecOps command-line tool (MIT licence, version 0.1.0), by Michael Awude (MikeOps).
- **How it works:** it runs proven free scanners plus its own GitHub Actions security audit, and merges the results into one prioritised list.
- **What you get:** a terminal summary, JSON and HTML reports, and an exit code your CI pipeline can act on.
- **Source:** https://github.com/dotmann-commits/mikeops-guard

The facts below were checked against the code and the built CLI on 18 October 2026.

---

## 1. The problem it solves

Most incidents in small teams are not exotic. They come from:
- a token committed months ago;
- a workflow that runs code from a fork with the repository's secrets;
- an action tag someone moved;
- a base image with a known vulnerability.

Each of these has a good free scanner, but every scanner has its own install, flags, output format and exit codes. MikeOps Guard gives you **one command, one policy file and one report**.

## 2. What it checks

| Area | What it finds | Engine |
|---|---|---|
| **Secrets** | API keys, tokens and passwords in files **and in git history**. Values are redacted and never written to reports | Gitleaks |
| **GitHub Actions security** | 9 built-in rules (section 3) | Built in |
| **GitHub Actions lint** | Syntax, expressions, runner labels, and ShellCheck on `run:` scripts | actionlint |
| **Dockerfiles** | Best practices, pinned base images, `ADD` versus `COPY`, apt hygiene | Hadolint |
| **Containers and infrastructure as code** | Dockerfile, Kubernetes, Helm and Terraform misconfiguration | Trivy (`trivy config`) |
| **Dependencies** | Known vulnerabilities in lockfiles for npm, pnpm, yarn, pip, Go, Cargo, Maven and more | osv-scanner (default) or Trivy |
| **AI explanations (optional)** | Plain-English risk, how it is exploited, and the fix, for the top findings | A **local** Ollama model. No paid APIs, nothing leaves your machine |

Scanner IDs, for `--only` and `--skip`: `gitleaks`, `workflow-audit`, `actionlint`, `hadolint`, `trivy-config`, `dependencies`.

## 3. Built-in GitHub Actions audit (`workflow-audit`)

| Rule ID | What it catches | Severity |
|---|---|---|
| `pull-request-target-checkout` | A `pull_request_target` job checks out the pull request's code, so a fork's code runs with secrets and a write token | **Critical** |
| `write-all-permissions` | The workflow grants the GitHub token `write-all` | High |
| `workflow-run-checkout` | A `workflow_run` job checks out code from the run that triggered it | High |
| `script-injection` | Untrusted input (issue or PR titles, bodies, comments, branch names) is placed directly inside a `run:` script | High |
| `unpinned-action` | A third-party action is not pinned to a commit SHA | Medium |
| `unpinned-action` | A GitHub-owned action is not pinned to a commit SHA | Low |
| `unpinned-docker-action` | A Docker action is not pinned to a digest | Medium |
| `pull-request-target-write-token` | A job triggered by `pull_request_target` has a write token | Medium |
| `missing-permissions` | No explicit GitHub token permissions are set | Low |
| `pull-request-target-trigger` | The workflow uses the risky `pull_request_target` trigger | Low |

Every finding explains the risk in plain English and gives a concrete fix. For example:

```text
CRITICAL pull_request_target checks out untrusted PR code
         .github/workflows/pr-preview.yml:10  [workflow-audit/pull-request-target-checkout]
         Job "preview" runs on pull_request_target, which has repository secrets and a write token,
         and checks out the pull request head. Any build, install or test step can then run code from a fork.
         Fix: Use the pull_request trigger for untrusted code. ...
```

## 4. Commands

| Command | What it does |
|---|---|
| `mikeops-guard scan [path]` | Scans a repository (default: the current folder) |
| `mikeops-guard doctor` | Shows which scanners and which local AI model are installed |
| `mikeops-guard init` | Writes a starter `.mikeops-guard.yml` policy file |
| `mikeops-guard --version`, `--help` | Version and help |

### Scan options

| Option | Effect |
|---|---|
| `-c, --config <file>` | Use a config file (default: `.mikeops-guard.yml` in the target) |
| `--fail-on <level>` | `critical`, `high`, `medium`, `low`, `info` or `none` (default `high`) |
| `--only <ids>` / `--skip <ids>` | Run only, or skip, the listed scanners |
| `--json <file>` | Write the JSON report (`-` for standard output) |
| `--html <file>` | Write a self-contained HTML report to share |
| `--explain` | Add local AI explanations to the top findings |
| `--model <name>` | Ollama model for `--explain` (default `llama3.2:3b`) |
| `--require-tools` | Fail instead of skipping when a scanner is missing (use in CI) |
| `--max-findings <n>` | Findings printed in the terminal (default 25) |
| `--no-color` | Plain output (`NO_COLOR` is also respected) |
| `-q, --quiet` | Print only the summary line |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Passed: no findings at or above the `--fail-on` level |
| `1` | Policy failed: at least one finding at or above that level |
| `2` | Usage or config error, for example an unknown flag or an invalid config |
| `3` | A scanner crashed, or was missing with `--require-tools` |

A policy failure (`1`) takes priority over a scanner failure (`3`), because it is the more actionable signal.

## 5. Policy file (`.mikeops-guard.yml`)

Each repository carries its own policy. Every key is optional, and **unknown keys are rejected**, so a typo can't silently switch off a check.

| Setting | Purpose |
|---|---|
| `failOn` | The severity that fails the run |
| `requireTools` | Missing scanners fail the run (CI) |
| `timeoutSeconds` | Time limit per scanner (default 300) |
| `exclude` | Paths dropped from scans and reports (globs) |
| `scanners.<id>.enabled` | Turn a scanner on or off |
| `scanners.gitleaks.mode` | `auto`, `git` (full history) or `dir` (working tree only) |
| `scanners.dependencies.engine` | `osv-scanner` or `trivy` |
| `ignore` | Accepted risks, each with a `reason`, matched by rule, `scanner:rule` or fingerprint, optionally limited to a path |
| `severityOverrides` | Change a rule's severity everywhere |
| `explain` | Local AI settings: host, model, how many findings, timeout |

Command-line flags override the file. Each tool's own config still applies, for example `.hadolint.yaml`, `.gitleaks.toml` and `.gitleaksignore`.

## 6. Reports

- **Terminal:** scanner status, findings sorted most severe first, a summary, and the pass or fail result.
- **JSON:** the full result for other tools and dashboards.
- **HTML:** a self-contained report to share with people. Every value is escaped, only `http(s)` links are allowed, and a strict Content Security Policy with no external resources is shipped.

## 7. GitHub Action

MikeOps Guard can run on every pull request and push. The action:
- builds the tool;
- installs **checksum-verified** scanner binaries;
- scans with `--require-tools`;
- writes `report.json` and `report.html`;
- exposes the result as the `exit-code` output.

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | Folder to scan |
| `fail-on` | `high` | Severity that fails the job |
| `config` | (none) | Config file path |
| `report-dir` | `mikeops-guard-report` | Where reports go |
| `install-scanners` | `true` | Set to `false` if the runner already has them |

It follows its own rules:
- The action's inputs are passed through environment variables, never placed inside the script, so they can't inject shell code.
- The example workflow pins every action to a commit SHA.

A complete example is in `examples/mikeops-guard.yml`.

## 8. Safety guarantees

- **Read-only.** A scan never writes to the repository it scans. Scanner output goes to a private temporary folder that is deleted afterwards. The test suite proves this by hashing the target before and after a scan.
- **No shell.** External tools are started with argument lists, never through a shell, so file names and config values can't inject commands.
- **Graceful degradation.** A missing scanner is skipped, with an install hint. In CI, `--require-tools` turns a missing scanner into a failure instead of a silent pass.
- **Scanner output is treated as untrusted data.** Every scanner's JSON is validated with zod before use.
- **Secrets stay secret.** Secret values are redacted and never written to reports or sent to the AI model.

## 9. Local AI explanations

`--explain` sends the top findings, most severe first, to a local Ollama model. It adds a short Risk, How it is exploited and Fix note to the terminal output and the HTML report.

- **Only finding metadata is sent:** rule, severity, file path, line and message. File contents and secret values never are.
- **It never blocks the scan.** If Ollama isn't running or the model is missing, the scan still completes and the report says why explanations were skipped.
- **Speed:** about 50 seconds per explanation on a laptop CPU with `llama3.2:3b`, so the default limit is 10 findings.
- **A bigger model on another machine** can be used by setting `explain.host`.

## 10. Network use

MikeOps Guard makes **no network calls of its own**, except to the Ollama host when `--explain` is on. Some scanners do:
- **Trivy** downloads its vulnerability database and checks on first run, and caches them in `~/.cache/trivy`.
- **osv-scanner** sends package names and versions (not your code) to the osv.dev API.

## 11. How it is built

- **Stack:** TypeScript on Node.js 20 or newer. Dependencies: `yaml` and `zod`.
- **Layout:** `cli/` (commands), `config/` (policy schema and loader), `core/` (file discovery, safe process execution, policy, orchestration), `scanners/` (one adapter per tool, plus `workflow-audit/` with one file per rule), `report/` (console, JSON, HTML), `explain/` (Ollama client).
- **Orchestration:** files are discovered once, then scanners run in parallel. Scanners that share a binary run one after another, because Trivy locks its cache. Excludes, ignores and severity overrides are applied, then one report is built.
- **Extending it:** add one adapter file, register it in `src/scanners/registry.ts`, and add its ID to `SCANNER_IDS`.

## 12. Verified on 18 October 2026

**All six scanners are installed on this Mac.** Hadolint 2.15.1, actionlint 1.7.12 and Gitleaks 8.30.1 came from Homebrew. Trivy 0.75.0 and osv-scanner 2.6.0 came from their official macOS releases through `scripts/install-scanners.sh`, verified against the published SHA-256 checksums. That took 10 seconds and about 236 MB, instead of a multi-gigabyte source build. Ollama has `llama3.2:3b` for `--explain`.

**A real scan of the bundled insecure sample repo** (`test/fixtures/sample-repo`) took about 6 seconds. It found **17 findings: 1 critical, 5 high, 6 medium and 5 low**, and the result was **FAILED at "high"**. The repository was unchanged afterwards.

| Scanner | Findings |
|---|---|
| Gitleaks | 0 |
| GitHub Actions audit | 5 |
| actionlint | 1 |
| Hadolint | 6 |
| Trivy (`trivy config`) | 5 |
| osv-scanner | 0 |

The sample has no vulnerable dependency pinned, so osv-scanner correctly finds nothing. The README's 26-finding example adds one old `jinja2` pin, which produces 9 dependency findings.

## 13. Roadmap (not built yet)

- SARIF output for GitHub code scanning alerts
- A baseline file, so only new findings fail the build
- Composite action and reusable workflow audits
- More workflow rules: self-hosted runners on public repos, `secrets: inherit`, cache poisoning, artifact poisoning in `workflow_run`
- Docker Compose checks: privileged containers, host network, secrets in `environment:`
- Container image scanning (`trivy image`)
- A prebuilt release and npm publish, for a one-command install
- A self-hosted runner guide

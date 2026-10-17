# Product Documentation

## Commands

| Command | Purpose |
|---|---|
| `mikeops-guard scan [path]` | Scan a repository |
| `mikeops-guard doctor` | Show installed scanners and Ollama status |
| `mikeops-guard init` | Write a starter `.mikeops-guard.yml`, never overwrites |

Full flag list: `mikeops-guard --help` or the repo README.

## Scanners

| Id | Engine | Finds |
|---|---|---|
| `gitleaks` | Gitleaks | Secrets in files and git history, redacted |
| `workflow-audit` | Built in | Unpinned actions, pull_request_target checkout, write-all and missing permissions, script injection |
| `actionlint` | actionlint | Workflow syntax, expressions, shellcheck |
| `hadolint` | Hadolint | Dockerfile best practices |
| `trivy-config` | Trivy | Dockerfile, Kubernetes, Helm, Terraform misconfiguration |
| `dependencies` | osv-scanner or Trivy | Known CVEs in lockfiles |

## Exit codes

`0` pass, `1` findings at or above `failOn`, `2` usage or config error, `3` scanner failed. Policy failure wins over scanner failure.

## Severity model

`critical > high > medium > low > info`. Each adapter maps the tool's own levels (see [[Backend]]). `severityOverrides` in config can change any rule.

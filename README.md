# MikeOps Guard

**Find exposed secrets, risky GitHub Actions, Dockerfile problems and vulnerable dependencies before you ship.**

MikeOps Guard is an open-source DevSecOps CLI. It runs proven free scanners (Gitleaks, actionlint, Hadolint, Trivy, osv-scanner) plus its own GitHub Actions security audit. It merges the results into one prioritised list and produces JSON and HTML reports. It sets an exit code your CI pipeline can act on.

Real output from scanning the deliberately insecure sample repo in `test/fixtures/sample-repo` (plus one old `jinja2` pin), with all scanners installed:

```text
$ mikeops-guard scan test/fixtures/sample-repo --max-findings 1

Scanners
  ok       Secret detection (Gitleaks)                  0 finding(s)
  ok       GitHub Actions security audit                5 finding(s)
  ok       Workflow lint (actionlint)                   1 finding(s)
  ok       Dockerfile lint (Hadolint)                   6 finding(s)
  ok       Container and IaC misconfiguration (Trivy)   5 finding(s)
  ok       Vulnerable dependencies                      9 finding(s)

Findings
  CRITICAL pull_request_target checks out untrusted PR code
           .github/workflows/pr-preview.yml:10  [workflow-audit/pull-request-target-checkout]
           Job "preview" runs on pull_request_target, which has repository secrets and a write token,
           and checks out the pull request head. Any build, install or test step can then run code from a fork.
           Fix: Use the pull_request trigger for untrusted code. ...

  ... and 25 more. Use --json or --html for the full list.

Summary: 26 finding(s) (1 critical, 9 high, 11 medium, 5 low), 0 ignored
Result:  FAILED: findings at or above "high"
```

## Why

Most incidents in small teams are not exotic. They come from a token committed six months ago, a `pull_request_target` workflow that runs fork code with secrets, an action tag that someone moved, or a base image with a known CVE. Each of these has a good free scanner, but each scanner has its own install, flags, output format and exit codes. MikeOps Guard gives you one command, one policy file and one report.

## Features

| Area | What it checks | Engine |
|---|---|---|
| Secrets | API keys, tokens and passwords in files **and in git history**. Values are redacted and never written to reports. | Gitleaks |
| GitHub Actions | Unpinned actions, `pull_request_target` checkouts of PR code, `write-all` and missing token permissions, script injection from issue/PR titles, bodies, comments and branch names | Built in |
| GitHub Actions | Syntax, expressions, runner labels, shellcheck on `run:` scripts | actionlint |
| Dockerfiles | Best practices, pinned base images, `ADD` vs `COPY`, apt hygiene | Hadolint |
| Containers and IaC | Dockerfile, Kubernetes, Helm and Terraform misconfiguration | Trivy (`trivy config`) |
| Dependencies | Known vulnerabilities in lockfiles for npm, pnpm, yarn, pip, Go, Cargo, Maven and more | osv-scanner (default) or Trivy |
| Web apps (AI-generated or not) | Server secrets in public frontend variables (`VITE_`, `NEXT_PUBLIC_`, `EXPO_PUBLIC_` and similar), the Supabase service role key in browser code, Supabase tables without Row Level Security, `using (true)` write policies, public storage buckets | Built in (`app-security`) |
| Reports | Terminal summary, JSON for tooling, self-contained HTML for people | Built in |
| AI explanations | Optional plain-English risk and fix notes from a **local** Ollama model. No paid APIs, nothing leaves your machine. | Ollama |

### Safety guarantees

- **Read-only.** Scans never write to the target repository. Scanner output goes to a private temp directory that is deleted after the run. The test suite checks this by hashing the target before and after a scan.
- **No shell.** External tools are started with argument arrays, never through a shell, so file names and config values cannot inject commands.
- **Never a silent pass.**
  - A scan where a scanner is missing, crashed, timed out or was disabled (by the config or `--only`/`--skip`) is reported as **INCOMPLETE**, never PASSED, and names what did not run.
  - Use `--require-tools` in CI so a missing scanner also fails the build.
  - A scanner with nothing to check, for example no Dockerfiles, is not a gap.
- **Untrusted output is treated as data.**
  - Every scanner's JSON is validated with zod.
  - Terminal output has control characters and bidi overrides removed, so repository content cannot hide findings or fake a verdict.
  - The HTML report escapes every value, links only `http(s)` URLs, and allows only its own script by hash under a strict Content Security Policy.
- **Secrets stay out of reports.**
  - Gitleaks values are never read.
  - Well-known credential formats are also redacted from every scanner message, error and AI explanation, and from anything sent to Ollama.
- **The scanned repository cannot redirect data.** Its own `.mikeops-guard.yml` may only use a local Ollama host. A remote host needs a trusted `--config`.
- **Binaries come from absolute PATH entries only**, so a scanned repository cannot plant a fake scanner.

Guard is static analysis. It finds known patterns and can miss real issues or flag safe code. Confirm findings before acting, and treat a clean result as "no known patterns found", not as proof of security.

## Install

Requires Node.js 20.3 or newer.

```bash
git clone https://github.com/dotmann-commits/mikeops-guard.git
cd mikeops-guard
npm ci
npm run build
npm link        # makes the mikeops-guard command available globally
```

Then install the scanners you want. Each one is optional.

**macOS**

```bash
brew install gitleaks actionlint hadolint
scripts/install-scanners.sh ~/.local/bin   # trivy and osv-scanner from official prebuilt releases
```

On Intel Macs Homebrew has no prebuilt packages for trivy and osv-scanner and compiles them from source, which can take gigabytes of disk. The script downloads the official macOS release binaries instead, verified against their published SHA-256 checksums. On Apple silicon `brew install trivy osv-scanner` also works.

**Linux (and CI)**

```bash
scripts/install-scanners.sh ~/.local/bin
```

The script downloads pinned releases from each project's GitHub releases page and verifies every file against the published SHA-256 checksums. Set `SCANNERS="trivy osv-scanner"` to install only some of them.

Check what is available:

```bash
mikeops-guard doctor
```

## Usage

```bash
mikeops-guard scan                         # scan the current directory
mikeops-guard scan ../my-app               # scan another directory
mikeops-guard scan --html report.html      # write a shareable HTML report
mikeops-guard scan --json report.json      # write a JSON report
mikeops-guard scan --json - | jq '.summary' # JSON to stdout, human output to stderr
mikeops-guard scan --only gitleaks,workflow-audit
mikeops-guard scan --skip dependencies
mikeops-guard scan --fail-on critical      # only fail on critical findings
mikeops-guard scan --explain               # add local AI explanations (see below)
mikeops-guard init                         # write a starter .mikeops-guard.yml
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Passed. No findings at or above `failOn`. |
| `1` | Policy failed. At least one finding at or above `failOn`. |
| `2` | Usage or config error, for example an unknown flag or invalid config. |
| `3` | A scanner crashed, or was missing with `requireTools` on. |
| `130` | Cancelled with Ctrl+C or SIGTERM. Scanners were stopped, temporary files removed, and no report was written. |

A policy failure (`1`) takes priority over a scanner failure (`3`), because it is the more actionable signal.

The JSON report's `status` is the full verdict: `passed` (no findings at the threshold and every applicable scanner ran), `failed` (findings at the threshold), or `incomplete` (no findings at the threshold, but coverage gaps). Each scanner outcome carries `incomplete: true` when it should have run but did not. `passed` keeps its 0.1.0 meaning, the policy result only.

Fingerprints ignore the line number, so ignore rules keep matching when code moves. Identical findings in one file are numbered. Ignore rules written with 0.1.0 fingerprints still match.

## Configuration

MikeOps Guard looks for `.mikeops-guard.yml` (or `.yaml` / `.json`) in the root of the scanned repository, so each repo carries its own policy. Pass `--config <file>` to use another file. Every key is optional. Unknown keys are rejected so typos do not silently disable a check.

```yaml
failOn: high              # critical | high | medium | low | info | none
requireTools: false       # true in CI: a missing scanner fails the run
timeoutSeconds: 300       # per scanner

exclude:                  # dropped from scans and reports (globs: **, *, ?)
  - "**/node_modules/**"
  - "test/fixtures/**"

scanners:
  gitleaks:
    enabled: true
    mode: auto            # auto | git (full history) | dir (working tree only)
  workflow-audit: { enabled: true }
  actionlint: { enabled: true }
  hadolint: { enabled: true }
  trivy-config: { enabled: true }
  dependencies:
    enabled: true
    engine: osv-scanner   # osv-scanner | trivy
  app-security: { enabled: true }

ignore:                   # accepted risks, matched by rule id, "scanner:rule" or fingerprint
  - rule: DL3008
    path: docker/legacy.Dockerfile
    reason: Versions pinned by the base image vendor

severityOverrides:        # change a rule's severity everywhere
  unpinned-action: high

explain:
  enabled: false
  host: http://127.0.0.1:11434
  model: llama3.2:3b
  maxFindings: 10
  timeoutSeconds: 120
```

Command-line flags override the file. Each tool's own config still applies, for example `.hadolint.yaml`, `.gitleaks.toml` and `.gitleaksignore` in the target repo.

## GitHub Actions

Add `.github/workflows/mikeops-guard.yml` to the repository you want to protect:

```yaml
name: MikeOps Guard
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0          # full history so Gitleaks sees old commits
          persist-credentials: false
      - uses: dotmann-commits/mikeops-guard@c4a4795d93952b85ca3c8bb8c4172e30bcb04167 # v0.1.0
        with:
          fail-on: high
      - if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: mikeops-guard-report
          path: mikeops-guard-report/
```

Pin the action to a commit SHA, the same rule MikeOps Guard enforces on your own workflows. The action installs checksum-verified scanners, runs with `--require-tools`, writes `report.json` and `report.html`, and exposes the exit code as the `exit-code` output. A complete copy is in [examples/mikeops-guard.yml](examples/mikeops-guard.yml).

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `fail-on` | `high` | Severity that fails the job |
| `config` | | Path to a config file |
| `report-dir` | `mikeops-guard-report` | Where reports are written |
| `install-scanners` | `true` | Set to `false` if your runner image already has them |

## Local AI explanations

`--explain` sends the top findings, most severe first, to a local [Ollama](https://ollama.com) model. It writes a short Risk, How it is exploited and Fix note into the terminal and the HTML report.

```bash
ollama pull llama3.2:3b
ollama serve                      # if it is not already running
mikeops-guard scan --explain
mikeops-guard scan --explain --model qwen2.5-coder:7b
```

Each explanation takes about 50 seconds on a laptop CPU with `llama3.2:3b`, so the default limit is 10 findings. Set `explain.maxFindings` lower for quick runs.

Only finding metadata is sent: rule, severity, file path, line and message. File contents and secret values are never sent. If Ollama is not running or the model is missing, the scan still completes and the report says why explanations were skipped. To use a bigger model on a separate GPU machine, set `explain.host` to that machine's address.

## Network use

MikeOps Guard makes no network calls of its own, except to the Ollama host when `--explain` is on. Some scanners do:

- **Trivy** downloads its vulnerability database and misconfiguration checks on first run and caches them in `~/.cache/trivy`.
- **osv-scanner** sends package names and versions (not your code) to the osv.dev API.

## How it works

```text
src/
  cli/          argument parsing, commands (scan, doctor, init), terminal I/O
  config/       zod schema and loader for .mikeops-guard.yml
  core/         types, file discovery, safe process execution, policy, orchestration
  scanners/     one adapter per tool, plus workflow-audit/ with one file per rule
  report/       console, JSON and HTML renderers
  explain/      Ollama client
```

Every scanner implements one small interface:

```ts
interface Scanner {
  id: ScannerId;
  title: string;
  category: Category;
  tool(config): ToolName | null;          // external binary, or null for built-in checks
  skipReason(ctx): string | null;         // e.g. "no Dockerfiles found"
  run(ctx): Promise<NewFinding[]>;
}
```

The orchestrator discovers files once, resolves binaries, and runs scanners in parallel. Scanners that share a binary run one after another, because Trivy locks its cache. It then applies excludes, ignores and severity overrides, and builds a single report. Adding a scanner means writing one adapter file, adding it to `src/scanners/registry.ts`, and adding its id to `SCANNER_IDS`.

### Why TypeScript and not Go

The scanners are already fast Go and Haskell binaries. MikeOps Guard's job is orchestration: validating JSON, applying policy and rendering reports. TypeScript with zod makes the JSON contracts explicit and testable. It also matches the stack used across MikeOps projects. The cost is a Node.js runtime, which every CI runner already has.

## Development

```bash
npm ci
npm run typecheck
npm run lint
npm test          # unit tests, plus real-scanner tests for each installed tool
npm run build
```

Integration tests in `test/integration/real-tools.test.ts` run the real scanners whenever they are on `PATH`, and are skipped otherwise. One test plants a randomly generated token in a throwaway git repo's history and checks that Gitleaks finds it and that the report never contains the value.

## Roadmap

- SARIF output for GitHub code scanning alerts.
- Baseline file, so existing findings are recorded and only new ones fail the build.
- Composite action (`action.yml`) and reusable workflow audits, not only `.github/workflows`.
- More workflow rules: self-hosted runners on public repos, `secrets: inherit`, cache poisoning, artifact poisoning in `workflow_run`.
- Docker Compose checks (privileged containers, host network, secrets in `environment:`).
- Container image scanning (`trivy image`) for images built in CI.
- Prebuilt release bundle and npm publish, so install is one command.
- Self-hosted runner guide, for running scans and a larger Ollama model on your own hardware.

## License

MIT. See [LICENSE](LICENSE).

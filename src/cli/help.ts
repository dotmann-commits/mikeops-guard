export const HELP_TEXT = `MikeOps Guard: find security issues and deployment risks before you ship.

Usage
  mikeops-guard scan [path] [options]   Scan a repository (default: current directory)
  mikeops-guard hook [path]             Silent fast guardrail for hooks and pre-commit
  mikeops-guard mcp [root]              Serve read-only scans to local MCP clients
  mikeops-guard doctor                  Show which scanners are installed
  mikeops-guard init                    Write a starter .mikeops-guard.yml here
  mikeops-guard --version | --help

Scan options
  -c, --config <file>        Config file (default: .mikeops-guard.yml in the target)
      --fail-on <level>      critical | high | medium | low | info | none (default: high)
      --only <ids>           Run only these scanners, comma separated
      --skip <ids>           Skip these scanners, comma separated
      --json <file>          Write the JSON report to a file ("-" for stdout)
      --html <file>          Write the HTML report to a file
      --sarif <file>         Write SARIF 2.1.0 for code scanning ("-" for stdout)
      --markdown <file>      Write a GitHub step-summary report ("-" for stdout)
      --explain              Explain top findings with a local Ollama model
      --model <name>         Ollama model for --explain (default: llama3.2:3b)
      --require-tools        Fail instead of skipping when a scanner is not installed
      --max-findings <n>     Findings to print in the terminal (default: 25)
      --no-color             Disable colors (NO_COLOR is also respected)
  -q, --quiet                Only print the summary line

Hook options
      --agent                Findings use stderr and exit 2 for agent hook feedback
      --fail-on <level>      Blocking threshold (default: high)

Init options
      --claude-hook         Install a Claude Code PostToolUse guard
      --cursor-hook         Install a Cursor afterFileEdit guard
      --pre-commit          Install a git pre-commit guard
      --skill               Install a minimal on-demand agent skill

Scanners
  gitleaks, workflow-audit, actionlint, hadolint, trivy-config, dependencies, app-security, ai-supply-chain

Exit codes
  0 passed   1 findings at or above --fail-on   2 usage or config error   3 a scanner failed
`;

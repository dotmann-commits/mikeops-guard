# Testing

`npm test` runs Vitest.

| Suite | Covers |
|---|---|
| `test/unit/workflow-audit.test.ts` | Every workflow rule, line numbers inside block scripts, parse errors |
| `test/unit/config.test.ts` | Defaults, partial config, JSON config, validation errors, root-only lookup |
| `test/unit/policy.test.ts` | Thresholds, ignores by rule, path, scanner and fingerprint, overrides, exit codes |
| `test/unit/html.test.ts` | XSS escaping, link filtering, CSP, no external assets |
| `test/unit/args.test.ts` | Flags, validation, CLI overrides do not mutate config |
| `test/unit/ollama.test.ts` | Model matching, ordering, limits, skip reasons, prompt content |
| `test/unit/glob.test.ts`, `tools.test.ts` | Glob matching, PATH lookup |
| `test/integration/cli.test.ts` | Real CLI on a fixture repo: exit codes, reports, skips, `--require-tools`, target unchanged |
| `test/integration/real-tools.test.ts` | Real scanners when installed: Gitleaks finds a generated token that only exists in history, Hadolint, actionlint, Trivy, osv-scanner |

The fixture repo `test/fixtures/sample-repo` is deliberately insecure and excluded from Guard's own policy.

| `test/unit/parsers.test.ts` | Every adapter against unedited output captured from the real tools in `test/fixtures/tool-output/` |

Real-scanner tests have a 180s timeout, because Trivy alone can take over 5s.

## Results 2026-10-17

- Mac (hadolint, actionlint, gitleaks installed): 78 passed, 2 skipped (trivy, osv-scanner).
- Linux container `node:22-bookworm-slim` with all five scanners from `install-scanners.sh`: 80 of 80 passed. Typecheck and lint clean.
- `npm audit`: 0 vulnerabilities.

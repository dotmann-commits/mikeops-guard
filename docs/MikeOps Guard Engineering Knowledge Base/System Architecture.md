# System Architecture

```text
CLI (args, commands) -> config loader (zod) -> orchestrator (core/run.ts)
                                                 |-> discover files once (read-only walk)
                                                 |-> resolve binaries on PATH
                                                 |-> scanners, grouped by binary
                                                 |     gitleaks | workflow-audit | actionlint
                                                 |     hadolint | trivy-config | dependencies
                                                 |-> policy: exclude, ignore, severity overrides, sort
                                                 '-> Report -> console | JSON | HTML
                                                       '-> optional Ollama explanations
```

## Layers

| Folder | Responsibility |
|---|---|
| `src/cli` | Parse args, run commands, terminal I/O behind a `CliIo` interface |
| `src/config` | Schema with defaults, loader, readable validation errors |
| `src/core` | Types, discovery, `execCommand`, tool lookup, globbing, policy, orchestration |
| `src/scanners` | One adapter per tool, `workflow-audit/` with one file per rule |
| `src/report` | Console, JSON, HTML renderers and HTML escaping |
| `src/explain` | Ollama client |

## Key design points

- Each adapter separates `run` (exec the tool) from a pure `parseX(stdout, root)` function, so parsing is unit-tested against real captured output.
- Scanners sharing a binary run one after another, because Trivy locks its cache. Different binaries run in parallel.
- Findings get a stable fingerprint (sha256 of scanner, rule, file, line, message) for ignores and future baselines.
- Dependencies are injected (`exec`, `resolveBinary`, `fetch`), so tests need no global mocks.

See [[ADR-001 TypeScript orchestrator over Go]] and [[ADR-002 Read-only scanning contract]].

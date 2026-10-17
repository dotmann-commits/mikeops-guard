# APIs

## JSON report (schemaVersion 1)

```text
Report { schemaVersion, tool{name,version}, target, startedAt, finishedAt, durationMs,
         failOn, passed, summary{critical,high,medium,low,info,total,ignored},
         scanners[ScannerOutcome], findings[Finding], explain? }
Finding { fingerprint, scanner, ruleId, title, severity, category, file?, line?,
          message, remediation?, references[], explanation? }
ScannerOutcome { scanner, title, status ok|skipped|failed, durationMs, findingCount, reason?, installHint? }
```

Types live in `src/core/types.ts`. Bump `schemaVersion` on any breaking change.

## GitHub Action

Inputs `path`, `fail-on`, `config`, `report-dir`, `install-scanners`. Output `exit-code`.

## External APIs used

Ollama `GET /api/tags` and `POST /api/generate`, only with `--explain`.

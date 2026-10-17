# Observability

A CLI has no runtime telemetry, and Guard sends none.

- Per-scanner status, duration, finding count and reason are in every report (`report.scanners`).
- JSON reports are the machine-readable record. In CI the action uploads them as an artifact.
- Unexpected errors print the stack trace to stderr and exit 3. Expected errors print one friendly line.
- `mikeops-guard doctor` is the health check for a machine.

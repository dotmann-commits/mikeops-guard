# ADR-002 Read-only scanning contract

Date: 2026-10-17. Status: accepted.

**Decision.** A scan must never write inside the target. Tools that need an output file (Gitleaks) write to a private temp dir. Discovery does not follow symlinks. Reports are only written where the user points `--json` or `--html`.

**Verification.** The integration tests hash the target before and after. The n8n-workflows validation compared file hashes and `git status`, and also ran from a read-only Docker mount.

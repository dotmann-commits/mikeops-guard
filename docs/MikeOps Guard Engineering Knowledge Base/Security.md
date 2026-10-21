# Security

## Guarantees

| Guarantee | How |
|---|---|
| Never modifies the target | Tool output goes to a private `mkdtemp` dir, removed in `finally`. Discovery does not follow symlinks. Tests hash the target before and after. A read-only Docker mount was also used in validation. |
| No command injection | `spawn` with argument arrays, never a shell |
| Secrets never in reports | Gitleaks runs with `--redact`, and the zod schema for its output has no `Secret` or `Match` field, so those values are dropped at parse time |
| Untrusted scanner output | Every tool's JSON is validated with zod before use |
| Safe HTML | All values escaped, only `http(s)` links, `rel="noopener noreferrer"`, CSP `default-src 'none'`, no external assets |
| Policy belongs to the repo | Config loads only from the target root or explicit `--config` ([[ADR-003 Config only from the scanned repo]]) |
| Strict config | Unknown keys rejected, Ollama host must be http or https |
| Supply chain | Scanner releases pinned and checksum-verified, releases younger than about two weeks avoided |

## Threat notes

- Scanning an untrusted repo runs the scanners on its files. None of the scanners execute repo code. Repo-level tool configs (`.gitleaks.toml`, `.hadolint.yaml`) are honoured by design, so a malicious repo can quiet its own findings. Use `--config` with your own policy when auditing third-party code.
- osv-scanner sends package names and versions to osv.dev. Trivy downloads its database.

## Hardening, 18 October 2026

See [the audit](../AUDIT-2026-10-18.md) for evidence, measurements and remaining risks.

- **Incomplete scans are never PASSED.** `status` is `passed`, `failed` or `incomplete`. Each scanner outcome says whether it should have run but did not.
- **Untrusted text is made safe:**
  - terminal output is stripped of control characters and bidi overrides;
  - the HTML report allows only its own script, by hash;
  - credential formats are redacted from every message, error and AI explanation.
- **The scanned repository is untrusted.**
  - Its config cannot send findings to a remote Ollama host.
  - Relative PATH entries are never used to find scanners.
- **Fingerprints (version 2) ignore line numbers.** Version 1 ignore rules still match.
- **New `app-security` scanner:**
  - checks: public frontend secrets, the Supabase service role in browser code, tables without RLS, permissive write policies and public buckets;
  - benchmarked on labelled fixtures and real projects.

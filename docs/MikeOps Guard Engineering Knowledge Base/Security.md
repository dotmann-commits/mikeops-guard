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

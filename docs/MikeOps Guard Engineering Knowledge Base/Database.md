# Database

None. MikeOps Guard is stateless. The only persisted data are the reports the user asks for with `--json` and `--html`.

Scanners keep their own caches outside the target repo: Trivy in `~/.cache/trivy`, osv-scanner in memory. A future baseline feature would store fingerprints in a file in the repo (see [[Future Roadmap]]).

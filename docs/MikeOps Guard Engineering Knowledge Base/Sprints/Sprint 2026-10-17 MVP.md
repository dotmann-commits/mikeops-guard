# Sprint 2026-10-17 MVP

**Goal.** Working MVP of MikeOps Guard with tests, docs and real-repo validation.

**Done.**
- Core, config, six scanners, workflow audit with 4 rule families, console, JSON and HTML reports, Ollama explainer, `scan`, `doctor`, `init`.
- Composite action, pinned checksum-verified installer, sample workflow, CI with dogfooding.
- Validated on a mirror clone of `dotmann-commits/n8n-workflows`: Gitleaks scanned all 4 commits, 0 findings, target unchanged.
- Found and fixed the config lookup bug ([[ADR-003 Config only from the scanned repo]]).

**Bugs found by validation and fixed.**
- Config was read from the working directory as well as the target ([[ADR-003 Config only from the scanned repo]]).
- osv fix version showed a git commit hash for 2 of 9 jinja2 advisories. Now only version ranges are used.
- HTML report scrolled sideways on phones. The scanner table now scrolls inside its own box, and long strings wrap.
- Real-scanner tests hit Vitest's 5s default timeout. Now 180s, with cleanup in `finally`.

**Results.** 80 of 80 tests in Linux with all five scanners. Full scan of the sample repo: 26 findings across all six scanners, exit 1. n8n-workflows scanned from a read-only mount: 0 findings, target unchanged. Guard passes its own policy. Real Ollama explanations verified.

**Shipped.** Public repo created, first CI run green (the action ran on a real runner), tagged v0.1.0.

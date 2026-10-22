# Executive Overview

MikeOps Guard turns five free security scanners plus a built-in GitHub Actions audit into one command, one policy file and one report.

**Problem.** Small teams ship secrets in git history, `pull_request_target` workflows that run fork code with secrets, mutable action tags and vulnerable base images. Good free scanners exist for each, but each has its own install, flags, output and exit codes, so most teams run none of them.

**Outcome.** `mikeops-guard scan` gives a prioritised list with file and line, a fix for each finding, JSON and HTML reports, and an exit code CI can gate on.

**Origin.** Built right after a manual security audit of the public `dotmann-commits` repos (n8n-workflows sanitised, MikeOps-dashboard debug endpoint fixed). This tool automates that audit.

**Status 2026-10-22.** v0.2.0 released: hardening from the 18 October audit, bounded file reads, process-group kills and clean Ctrl+C. v0.1.0 (MVP) was published 2026-10-17.

**Audience.** MikeOps client projects, MikeOps own repos, and open source users. It is also a portfolio piece for platform and DevSecOps roles.

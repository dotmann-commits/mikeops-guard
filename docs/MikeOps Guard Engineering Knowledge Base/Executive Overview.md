# Executive Overview

MikeOps Guard turns five free security scanners plus a built-in GitHub Actions audit into one command, one policy file and one report.

**Problem.** Small teams ship secrets in git history, `pull_request_target` workflows that run fork code with secrets, mutable action tags and vulnerable base images. Good free scanners exist for each, but each has its own install, flags, output and exit codes, so most teams run none of them.

**Outcome.** `mikeops-guard scan` gives a prioritised list with file and line, a fix for each finding, JSON and HTML reports, and an exit code CI can gate on.

**Origin.** Built right after a manual security audit of the public `dotmann-commits` repos (n8n-workflows sanitised, MikeOps-dashboard debug endpoint fixed). This tool automates that audit.

**Status 2026-10-17.** MVP built and validated. Not committed, not published.

**Audience.** MikeOps client projects, MikeOps own repos, and open source users. It is also a portfolio piece for platform and DevSecOps roles.

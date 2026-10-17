# 2026-10-17 Disk filled by Homebrew source build

**Impact.** Free disk on the Mac dropped to about 6 GB and macOS asked Michael to manage storage. Machine load reached about 530 and slowed other sessions.

**Cause.** `brew install trivy osv-scanner` had no prebuilt bottle for this Intel macOS, so Homebrew installed Go and compiled both from source. That created about 9 GB: Go build and module caches (6.6 GB), the build folder in /private/tmp (2.7 GB) and Go itself (551 MB). The earlier advice that no stronger machine was needed considered CPU and memory but not this.

**Resolution.** Stopped the build, removed only the artifacts it created, installed the small bottled tools (actionlint, gitleaks), and moved Trivy and osv-scanner validation into a throwaway Linux container using the project's own installer. Michael also pruned unused Docker images, the npm cache and the Homebrew cache. Free space ended at about 24 GB.

**Lessons.**
- Check for bottles (`brew info --json=v2 <formula>`) before installing on this Mac.
- Prefer prebuilt release binaries or a container for Go tools on Intel macOS.
- Account for disk, not only CPU and memory, when judging whether a machine is enough.

# ADR-003 Config only from the scanned repo

Date: 2026-10-17. Status: accepted.

**Context.** The first loader also searched the current working directory. Validation showed Guard's own `.mikeops-guard.yml` being applied when scanning n8n-workflows from the Guard folder.

**Decision.** Load `.mikeops-guard.yml` only from the target root, or from an explicit `--config`. `doctor` and `init` use the working directory because they have no target.

**Why.** A policy that depends on where the command runs is surprising and can silently hide findings.

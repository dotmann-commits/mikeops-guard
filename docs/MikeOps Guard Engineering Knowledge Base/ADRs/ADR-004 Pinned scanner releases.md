# ADR-004 Pinned scanner releases

Date: 2026-10-17. Status: accepted.

**Decision.** `scripts/install-scanners.sh` pins exact versions (hadolint 2.15.1, trivy 0.75.0, actionlint 1.7.12, gitleaks 8.30.1, osv-scanner 2.6.0) and verifies every download against the release's SHA-256 checksum file.

**Why.** A security tool must not pull whatever is latest. Trivy itself had a release compromise earlier in 2026. Brand-new releases (trivy 0.76.0 and osv-scanner 2.7.0, each a few days old) were skipped in favour of releases at least two weeks old.

**Limit.** A checksum file from the same release protects against corruption and tampering in transit, not against a compromised release. Signature checks (cosign) are a future improvement.

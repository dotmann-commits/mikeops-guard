# Update pinned scanner versions

Why: pinned versions go stale and miss new detection rules, but updating blindly defeats the pin.

1. List releases: `gh api repos/aquasecurity/trivy/releases?per_page=5 -q '.[].tag_name + " " + .published_at'` (repeat per tool).
2. Pick a release at least two weeks old. Read its changelog and any security advisories for the project.
3. Update the version variable in `scripts/install-scanners.sh`. Check the asset names still match.
4. Test in a container: `docker run --rm -v "$PWD/scripts:/s:ro" ubuntu:24.04 bash -c 'apt-get update -qq && apt-get install -y -qq curl ca-certificates && bash /s/install-scanners.sh /opt/bin'`
5. Run `npm test` with the new tools on PATH, then update [[ADR-004 Pinned scanner releases]].

# Deployment

Published 2026-10-17 as a public GitHub repo: https://github.com/dotmann-commits/mikeops-guard

- `main` is protected only by CI (check plus dogfood). Both passed on the first push.
- Releases are git tags (`v0.1.0` first). Users pin the action by the tag's commit SHA, with the tag in a comment.
- Not on npm yet. A prebuilt `dist/` bundle so the action skips `npm ci` is on the [[Future Roadmap]].

## Releasing a new version

1. Bump `version` in `package.json`, run `npm run check`, commit.
2. `git tag -a vX.Y.Z -m "MikeOps Guard vX.Y.Z"` and `git push origin vX.Y.Z`. Why: the tag gives users a fixed reference to pin.
3. `gh release create vX.Y.Z --verify-tag --notes-file <notes>`.
4. Update the pinned SHA in `README.md` and `examples/mikeops-guard.yml`.

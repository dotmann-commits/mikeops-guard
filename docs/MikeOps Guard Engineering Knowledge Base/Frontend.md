# Frontend

There is no web app. The two user-facing surfaces are:

1. **Terminal output** (`src/report/console.ts`). Colour only on a TTY, respects `NO_COLOR` and `--no-color`. With `--json -` human output moves to stderr so stdout stays valid JSON.
2. **HTML report** (`src/report/html.ts`). One self-contained file. Inline CSS and a tiny severity filter script. Works offline. Light and dark through `prefers-color-scheme`. Strict CSP with `default-src 'none'`.

See [[Design System]] for colours and layout.

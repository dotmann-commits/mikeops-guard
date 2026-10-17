# AI Systems

Optional and local only. No paid AI APIs.

- Client: `src/explain/ollama.ts`, uses `GET /api/tags` to check the model is pulled, and `POST /api/generate` with `stream: false` and temperature 0.2.
- Prompt: a fixed system prompt asking for Risk, How it is exploited and Fix in under 120 words. The user prompt holds finding metadata only: scanner, rule, severity, title, location, message, suggested fix. No file contents. Gitleaks secret values never reach a `Finding`, so they cannot reach the prompt.
- Output cleaning: small models add markdown and a preamble ("Here's the review"). `cleanExplanation` strips `**`, backticks and headings, and starts the text at "Risk".
- Speed: about 50 seconds per finding with `llama3.2:3b` on the Intel Mac CPU, verified 2026-10-17. Keep `maxFindings` low locally, or use a GPU host.
- Order: most severe first, up to `explain.maxFindings` (default 10), one request at a time so a laptop GPU is not overloaded.
- Failure: Ollama down or model missing means the scan still finishes and `report.explain.reason` tells the user what to run (`ollama serve`, `ollama pull <model>`).
- Default model `llama3.2:3b` runs on the Mac. A bigger model can run on the HP Victus by pointing `explain.host` at it.

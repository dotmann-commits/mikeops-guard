# ADR-001 TypeScript orchestrator over Go

Date: 2026-10-17. Status: accepted.

**Context.** The scanners are Go and Haskell binaries. Guard shells out to them and processes their JSON.

**Decision.** Write Guard in strict TypeScript on Node 20+, with zod and yaml as the only runtime dependencies. Use `node:util parseArgs` instead of a CLI framework.

**Why.** The hard part is JSON contracts, policy and reports, where zod gives explicit and testable schemas. It matches the MikeOps stack, so Michael can maintain it. Node is on every CI runner.

**Trade-off.** No single static binary. Accepted, and a bundled release is on the roadmap.

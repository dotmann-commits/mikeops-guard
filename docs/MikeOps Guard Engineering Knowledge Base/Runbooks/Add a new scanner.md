# Add a new scanner

1. Add the id to `SCANNER_IDS` in `src/core/types.ts`, and a toggle in `src/config/schema.ts`.
2. If it needs a binary, add it to `TOOLS` in `src/core/tools.ts` with version args and install hints.
3. Create `src/scanners/<id>.ts` with a zod schema for the tool output, a pure `parse<Id>(stdout, root)` and a `Scanner` object. List every success exit code explicitly.
4. Register it in `src/scanners/registry.ts`.
5. Capture real output into `test/fixtures/tool-output/` and unit-test the parser. Add a `skipIf` case to `test/integration/real-tools.test.ts`.
6. Add the binary to `scripts/install-scanners.sh` with checksum verification.
7. Update README, [[Product Documentation]] and [[Backend]].

import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { UsageError } from '../../core/errors.js';
import type { CliIo } from '../io.js';

export const STARTER_CONFIG = `# MikeOps Guard configuration. Every key is optional.
# Docs: https://github.com/dotmann-commits/mikeops-guard#configuration

# Exit with code 1 when any finding is at or above this level.
# critical | high | medium | low | info | none
failOn: high

# Fail the run, instead of skipping, when a scanner binary is missing. Recommended in CI.
requireTools: false

timeoutSeconds: 300

# Paths to leave out of scans and reports (glob syntax: **, *, ?).
exclude:
  - "**/node_modules/**"
  - "**/vendor/**"

scanners:
  gitleaks:
    enabled: true
    mode: auto          # auto | git (full history) | dir (working tree only)
  workflow-audit:
    enabled: true
  actionlint:
    enabled: true
  hadolint:
    enabled: true
  trivy-config:
    enabled: true
  dependencies:
    enabled: true
    engine: osv-scanner # osv-scanner | trivy

# Accepted risks. Match by rule id, "scanner:rule" or fingerprint, optionally limited to a path.
ignore: []
#  - rule: DL3008
#    path: docker/legacy.Dockerfile
#    reason: Pinned by the base image vendor

# Change the severity of a rule everywhere.
severityOverrides: {}
#  unpinned-action: high

# Optional plain-English explanations from a local Ollama model. Nothing leaves your machine.
explain:
  enabled: false
  host: http://127.0.0.1:11434
  model: llama3.2:3b
  maxFindings: 10
`;

export async function initCommand(io: CliIo): Promise<number> {
  const file = path.join(io.cwd, '.mikeops-guard.yml');
  try {
    // "wx" refuses to overwrite, so an existing policy is never lost.
    await writeFile(file, STARTER_CONFIG, { encoding: 'utf8', flag: 'wx' });
  } catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST') {
      throw new UsageError(`${file} already exists. Edit it or delete it first.`);
    }
    throw error;
  }
  io.stdout(`Created ${file}\n`);
  return 0;
}

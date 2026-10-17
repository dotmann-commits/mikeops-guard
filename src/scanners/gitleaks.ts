import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import type { ScanContext, Scanner } from '../core/scanner.js';
import type { NewFinding } from '../core/types.js';
import { definedOnly, parseJson, relativeToRoot, runTool } from './shared.js';

// Secret and Match fields are deliberately left out of the schema so they never reach a report.
const leaksSchema = z
  .array(
    z.object({
      RuleID: z.string(),
      Description: z.string(),
      File: z.string(),
      StartLine: z.number(),
      Commit: z.string().optional(),
    }),
  )
  .nullable();

export function parseGitleaks(raw: string, root: string): NewFinding[] {
  if (!raw.trim()) return [];
  return (parseJson(raw, leaksSchema, 'gitleaks') ?? []).map((leak) => {
    const commit = leak.Commit ? leak.Commit.slice(0, 12) : undefined;
    return definedOnly({
      scanner: 'gitleaks' as const,
      ruleId: leak.RuleID,
      title: `Possible secret: ${leak.Description}`,
      severity: 'critical' as const,
      category: 'secret' as const,
      file: relativeToRoot(root, leak.File),
      line: leak.StartLine > 0 ? leak.StartLine : undefined,
      message: commit
        ? `A value matching "${leak.RuleID}" was found in git history (commit ${commit}). Removing it from the latest commit does not remove it from history.`
        : `A value matching "${leak.RuleID}" was found in the working tree.`,
      remediation:
        'Treat the secret as compromised: revoke and rotate it first. Then remove it from the code and, if needed, from history with git filter-repo. Mark confirmed false positives in .gitleaksignore.',
      references: ['https://github.com/gitleaks/gitleaks#readme'],
    });
  });
}

function scanMode(ctx: ScanContext): 'git' | 'dir' {
  const mode = ctx.config.scanners.gitleaks.mode;
  if (mode !== 'auto') return mode;
  return ctx.isGitRepo ? 'git' : 'dir';
}

export const gitleaksScanner: Scanner = {
  id: 'gitleaks',
  title: 'Secret detection (Gitleaks)',
  category: 'secret',
  tool: () => 'gitleaks',
  skipReason: (ctx) =>
    ctx.config.scanners.gitleaks.mode === 'git' && !ctx.isGitRepo ? 'mode is "git" but the target is not a git repository' : null,
  async run(ctx) {
    // The report goes to our temp dir, never into the target. --redact keeps secrets out of it.
    const reportPath = path.join(ctx.tempDir, 'gitleaks.json');
    await runTool(ctx, [
      scanMode(ctx),
      '--report-format',
      'json',
      '--report-path',
      reportPath,
      '--redact',
      '--exit-code',
      '0',
      '--no-banner',
      '--log-level',
      'error',
      '.',
    ]);
    return parseGitleaks(await readFile(reportPath, 'utf8'), ctx.root);
  },
};

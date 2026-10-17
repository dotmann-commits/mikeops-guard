import { z } from 'zod';
import type { Scanner } from '../core/scanner.js';
import type { NewFinding } from '../core/types.js';
import { definedOnly, parseJson, relativeToRoot, runTool, severityFromLabel } from './shared.js';

const misconfigSchema = z.object({
  ID: z.string(),
  AVDID: z.string().optional(),
  Title: z.string(),
  Description: z.string().optional(),
  Message: z.string().optional(),
  Resolution: z.string().optional(),
  Severity: z.string(),
  PrimaryURL: z.string().optional(),
  References: z.array(z.string()).nullish(),
  Status: z.string(),
  CauseMetadata: z.object({ StartLine: z.number().optional() }).optional(),
});

const reportSchema = z.object({
  Results: z
    .array(
      z.object({
        Target: z.string(),
        Type: z.string().optional(),
        Misconfigurations: z.array(misconfigSchema).nullish(),
      }),
    )
    .nullish(),
});

export function parseTrivyConfig(stdout: string, root: string): NewFinding[] {
  const report = parseJson(stdout, reportSchema, 'trivy config');
  return (report.Results ?? []).flatMap((result) =>
    (result.Misconfigurations ?? [])
      .filter((m) => m.Status === 'FAIL')
      .map((m) =>
        definedOnly({
          scanner: 'trivy-config' as const,
          ruleId: m.ID,
          title: m.Title,
          severity: severityFromLabel(m.Severity),
          category: result.Type === 'dockerfile' ? ('container' as const) : ('iac' as const),
          file: relativeToRoot(root, result.Target),
          line: m.CauseMetadata?.StartLine || undefined,
          message: m.Message ?? m.Description ?? m.Title,
          remediation: m.Resolution,
          references: [...new Set([m.PrimaryURL, ...(m.References ?? [])].filter((r): r is string => Boolean(r)))].slice(0, 3),
        }),
      ),
  );
}

export function skipDirArgs(exclude: readonly string[]): string[] {
  return exclude.flatMap((pattern) => ['--skip-dirs', pattern.replace(/\/\*\*$/, '')]);
}

export const trivyConfigScanner: Scanner = {
  id: 'trivy-config',
  title: 'Container and IaC misconfiguration (Trivy)',
  category: 'iac',
  tool: () => 'trivy',
  skipReason: () => null,
  async run(ctx) {
    const { stdout } = await runTool(ctx, [
      'config',
      '--format',
      'json',
      '--quiet',
      '--exit-code',
      '0',
      ...skipDirArgs(ctx.config.exclude),
      '.',
    ]);
    return parseTrivyConfig(stdout, ctx.root);
  },
};

import { z } from 'zod';
import type { Scanner } from '../core/scanner.js';
import type { NewFinding, Severity } from '../core/types.js';
import { definedOnly, parseJson, relativeToRoot, runTool } from './shared.js';

const errorsSchema = z
  .array(
    z.object({
      message: z.string(),
      filepath: z.string(),
      line: z.number(),
      kind: z.string(),
    }),
  )
  .nullable();

const KIND_SEVERITY: Record<string, Severity> = {
  credentials: 'high',
  expression: 'medium',
  permissions: 'medium',
  action: 'medium',
  shellcheck: 'low',
  pyflakes: 'low',
};

export function parseActionlint(stdout: string, root: string): NewFinding[] {
  if (!stdout.trim()) return [];
  return (parseJson(stdout, errorsSchema, 'actionlint') ?? []).map((item) =>
    definedOnly({
      scanner: 'actionlint' as const,
      ruleId: `actionlint-${item.kind}`,
      title: `Workflow ${item.kind} issue`,
      severity: KIND_SEVERITY[item.kind] ?? 'medium',
      category: 'workflow' as const,
      file: relativeToRoot(root, item.filepath),
      line: item.line > 0 ? item.line : undefined,
      message: item.message,
      references: ['https://github.com/rhysd/actionlint/blob/main/docs/checks.md'],
    }),
  );
}

export const actionlintScanner: Scanner = {
  id: 'actionlint',
  title: 'Workflow lint (actionlint)',
  category: 'workflow',
  tool: () => 'actionlint',
  skipReason: (ctx) => (ctx.files.workflows.length === 0 ? 'no GitHub Actions workflows found' : null),
  async run(ctx) {
    // Exit code 1 means "problems found", which is a normal result here.
    const { stdout } = await runTool(ctx, ['-format', '{{json .}}', '-no-color', ...ctx.files.workflows], [0, 1]);
    return parseActionlint(stdout, ctx.root);
  },
};

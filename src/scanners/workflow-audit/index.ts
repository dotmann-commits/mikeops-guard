import path from 'node:path';
import { FILE_CONCURRENCY, mapLimit } from '../../core/concurrency.js';
import { readTextFile } from '../../core/files.js';
import type { Scanner } from '../../core/scanner.js';
import type { NewFinding } from '../../core/types.js';
import type { WorkflowRule } from './rule.js';
import { broadPermissions } from './rules/permissions.js';
import { pullRequestTarget } from './rules/pull-request-target.js';
import { scriptInjection } from './rules/script-injection.js';
import { unpinnedActions } from './rules/unpinned-actions.js';
import { parseWorkflow } from './workflow.js';

export const WORKFLOW_RULES: readonly WorkflowRule[] = [pullRequestTarget, scriptInjection, broadPermissions, unpinnedActions];

export function auditWorkflow(file: string, source: string, rules = WORKFLOW_RULES): NewFinding[] {
  const parsed = parseWorkflow(file, source);
  if (!parsed.ok) {
    return [
      {
        scanner: 'workflow-audit',
        ruleId: 'workflow-parse-error',
        title: 'Workflow file could not be parsed',
        severity: 'low',
        category: 'workflow',
        file,
        ...(parsed.line ? { line: parsed.line } : {}),
        message: parsed.error,
        references: [],
      },
    ];
  }
  return rules.flatMap((rule) =>
    rule(parsed.workflow).map(
      ({ line, ...hit }): NewFinding => ({
        scanner: 'workflow-audit',
        category: 'workflow',
        file,
        ...(line ? { line } : {}),
        ...hit,
      }),
    ),
  );
}

export const workflowAuditScanner: Scanner = {
  id: 'workflow-audit',
  title: 'GitHub Actions security audit',
  category: 'workflow',
  tool: () => null,
  skipReason: (ctx) => (ctx.files.workflows.length === 0 ? 'no GitHub Actions workflows found' : null),
  async run(ctx) {
    const results = await mapLimit(ctx.files.workflows, FILE_CONCURRENCY, async (file) => {
      const read = await readTextFile(path.join(ctx.root, file));
      if (!read.ok) {
        ctx.skipFile({ file, reason: read.reason, affectsCoverage: true });
        return [];
      }
      return auditWorkflow(file, read.text);
    });
    return results.flat();
  },
};

import { z } from 'zod';
import type { Scanner } from '../core/scanner.js';
import type { NewFinding, Severity } from '../core/types.js';
import { definedOnly, parseJson, relativeToRoot, runTool } from './shared.js';

const resultSchema = z.array(
  z.object({
    code: z.string(),
    level: z.string(),
    line: z.number(),
    message: z.string(),
    file: z.string(),
  }),
);

const LEVELS: Record<string, Severity> = { error: 'high', warning: 'medium', info: 'low', style: 'info' };

function referenceFor(code: string): string[] {
  if (code.startsWith('DL')) return [`https://github.com/hadolint/hadolint/wiki/${code}`];
  if (code.startsWith('SC')) return [`https://www.shellcheck.net/wiki/${code}`];
  return [];
}

function firstSentence(text: string): string {
  const end = text.search(/\.\s/);
  return end === -1 ? text : text.slice(0, end);
}

export function parseHadolint(stdout: string, root: string): NewFinding[] {
  if (!stdout.trim()) return [];
  return parseJson(stdout, resultSchema, 'hadolint').map((item) =>
    definedOnly({
      scanner: 'hadolint' as const,
      ruleId: item.code,
      title: firstSentence(item.message),
      severity: LEVELS[item.level] ?? 'medium',
      category: 'container' as const,
      file: relativeToRoot(root, item.file),
      line: item.line > 0 ? item.line : undefined,
      message: item.message,
      references: referenceFor(item.code),
    }),
  );
}

export const hadolintScanner: Scanner = {
  id: 'hadolint',
  title: 'Dockerfile lint (Hadolint)',
  category: 'container',
  tool: () => 'hadolint',
  skipReason: (ctx) => (ctx.files.dockerfiles.length === 0 ? 'no Dockerfiles found' : null),
  async run(ctx) {
    // --no-fail keeps exit code 0 when findings exist, so non-zero always means a real error.
    const { stdout } = await runTool(ctx, ['--no-fail', '--format', 'json', ...ctx.files.dockerfiles]);
    return parseHadolint(stdout, ctx.root);
  },
};

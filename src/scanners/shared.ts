import path from 'node:path';
import type { z } from 'zod';
import { errorMessage, ScannerError } from '../core/errors.js';
import { stderrTail, type ExecResult } from '../core/exec.js';
import { toPosix } from '../core/glob.js';
import type { ScanContext } from '../core/scanner.js';
import type { Severity } from '../core/types.js';

export function requireBinary(ctx: ScanContext): string {
  if (!ctx.binary) throw new ScannerError('Scanner binary was not resolved');
  return ctx.binary;
}

/** Runs the tool from the target root and rejects exit codes the tool does not document as success. */
export async function runTool(
  ctx: ScanContext,
  args: readonly string[],
  okCodes: readonly number[] = [0],
): Promise<ExecResult> {
  const binary = requireBinary(ctx);
  const result = await ctx.exec(binary, args, { cwd: ctx.root, timeoutMs: ctx.timeoutMs });
  if (!okCodes.includes(result.code)) {
    const detail = stderrTail(result.stderr) || stderrTail(result.stdout) || 'no output';
    throw new ScannerError(`${path.basename(binary)} exited with code ${result.code}: ${detail}`);
  }
  return result;
}

export function parseJson<T>(raw: string, schema: z.ZodType<T>, toolName: string): T {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    throw new ScannerError(`${toolName} returned output that is not JSON: ${errorMessage(error)}`);
  }
  const result = schema.safeParse(data);
  if (!result.success) {
    const issue = result.error.issues[0];
    throw new ScannerError(`${toolName} JSON did not match the expected format at ${issue?.path.join('.') ?? '(root)'}: ${issue?.message ?? 'unknown'}`);
  }
  return result.data;
}

/** Normalises a tool-reported path to a forward-slash path relative to the scan root. */
export function relativeToRoot(root: string, file: string): string {
  const absolute = path.isAbsolute(file) ? file : path.join(root, file);
  return toPosix(path.relative(root, absolute));
}

const UPPER_SEVERITY: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  MODERATE: 'medium',
  LOW: 'low',
};

/** Maps CRITICAL/HIGH/MEDIUM/LOW labels. Unknown labels become medium so they are not silently dropped. */
export function severityFromLabel(label: string | undefined): Severity {
  return UPPER_SEVERITY[(label ?? '').toUpperCase()] ?? 'medium';
}

/** CVSS base score bands from the CVSS v3 specification. */
export function severityFromCvss(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function definedOnly<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined && v !== '')) as T;
}

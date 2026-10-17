import { isMap, isScalar, isSeq, LineCounter, parseDocument, Scalar, type Document } from 'yaml';

export type YamlPath = readonly (string | number)[];

export interface WorkflowStep {
  path: YamlPath;
  uses?: string;
  run?: string;
  with: Record<string, unknown>;
}

export interface WorkflowJob {
  id: string;
  path: YamlPath;
  /** Reusable workflow reference, for jobs that call another workflow. */
  uses?: string;
  permissions: unknown;
  hasPermissions: boolean;
  steps: WorkflowStep[];
}

export interface Workflow {
  file: string;
  triggers: Set<string>;
  permissions: unknown;
  hasPermissions: boolean;
  jobs: WorkflowJob[];
  /** 1-based line of the node at a YAML path, if it exists. */
  lineAt(path: YamlPath): number | undefined;
  /** 1-based line of a given line index inside a multi-line string value. */
  lineInValue(path: YamlPath, lineIndex: number): number | undefined;
}

export type ParseResult = { ok: true; workflow: Workflow } | { ok: false; error: string; line?: number };

export function parseWorkflow(file: string, source: string): ParseResult {
  const lineCounter = new LineCounter();
  // YAML 1.2 keeps the "on" key as a string. YAML 1.1 would turn it into true.
  const doc = parseDocument(source, { lineCounter, version: '1.2' });
  const firstError = doc.errors[0];
  if (firstError) {
    return { ok: false, error: firstError.message, line: firstError.linePos?.[0].line };
  }
  const data: unknown = doc.toJS();
  if (!isRecord(data)) return { ok: false, error: 'Workflow is not a YAML mapping' };

  const lineAt = (path: YamlPath): number | undefined => {
    const node = doc.getIn(path, true);
    const offset = nodeOffset(node);
    return offset === undefined ? undefined : lineCounter.linePos(offset).line;
  };

  return {
    ok: true,
    workflow: {
      file,
      triggers: readTriggers(data.on),
      permissions: data.permissions,
      hasPermissions: 'permissions' in data,
      jobs: readJobs(data.jobs),
      lineAt,
      lineInValue: (path, lineIndex) => lineInValue(doc, path, lineIndex, lineAt),
    },
  };
}

function lineInValue(
  doc: Document,
  path: YamlPath,
  lineIndex: number,
  lineAt: (p: YamlPath) => number | undefined,
): number | undefined {
  const start = lineAt(path);
  if (start === undefined) return undefined;
  const node = doc.getIn(path, true);
  const isBlock = isScalar(node) && (node.type === Scalar.BLOCK_LITERAL || node.type === Scalar.BLOCK_FOLDED);
  // Block scalars start on the line after the "|" or ">" indicator.
  return isBlock ? start + 1 + lineIndex : start;
}

function nodeOffset(node: unknown): number | undefined {
  if (isScalar(node) || isMap(node) || isSeq(node)) return node.range?.[0];
  return undefined;
}

function readTriggers(on: unknown): Set<string> {
  if (typeof on === 'string') return new Set([on]);
  if (Array.isArray(on)) return new Set(on.filter((t): t is string => typeof t === 'string'));
  if (isRecord(on)) return new Set(Object.keys(on));
  return new Set();
}

function readJobs(jobs: unknown): WorkflowJob[] {
  if (!isRecord(jobs)) return [];
  return Object.entries(jobs).flatMap(([id, job]): WorkflowJob[] => {
    if (!isRecord(job)) return [];
    const path = ['jobs', id];
    return [
      {
        id,
        path,
        ...(typeof job.uses === 'string' ? { uses: job.uses } : {}),
        permissions: job.permissions,
        hasPermissions: 'permissions' in job,
        steps: readSteps(job.steps, path),
      },
    ];
  });
}

function readSteps(steps: unknown, jobPath: YamlPath): WorkflowStep[] {
  if (!Array.isArray(steps)) return [];
  return steps.flatMap((step: unknown, index): WorkflowStep[] => {
    if (!isRecord(step)) return [];
    return [
      {
        path: [...jobPath, 'steps', index],
        ...(typeof step.uses === 'string' ? { uses: step.uses } : {}),
        ...(typeof step.run === 'string' ? { run: step.run } : {}),
        with: isRecord(step.with) ? step.with : {},
      },
    ];
  });
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

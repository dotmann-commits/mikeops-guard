import { readFile, stat } from 'node:fs/promises';
import { UsageError } from './errors.js';
import type { ExecFn } from './exec.js';
import { countBySeverity, meetsThreshold } from './policy.js';
import type { Report } from './types.js';

const MAX_BASELINE_BYTES = 50 * 1024 * 1024;

interface BaselineScope {
  label: string;
  fingerprints: ReadonlySet<string>;
}

interface ChangedScope {
  ref: string;
  files: ReadonlySet<string>;
}

export interface FindingScope {
  baseline?: BaselineScope;
  changed?: ChangedScope;
}

function fingerprintsFrom(value: unknown): string[] | undefined {
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) return value;
  if (!value || typeof value !== 'object') return undefined;
  const record = value as Record<string, unknown>;
  if (Array.isArray(record.fingerprints) && record.fingerprints.every((item) => typeof item === 'string')) return record.fingerprints;
  if (Array.isArray(record.findings)) {
    const fingerprints = record.findings.map((item) =>
      item && typeof item === 'object' ? (item as Record<string, unknown>).fingerprint : undefined,
    );
    if (fingerprints.every((item) => typeof item === 'string')) return fingerprints;
  }
  return undefined;
}

export function parseBaseline(source: string): Set<string> {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new UsageError('Baseline must be valid JSON from a previous MikeOps report or a fingerprint array');
  }
  const fingerprints = fingerprintsFrom(value);
  if (!fingerprints) throw new UsageError('Baseline must contain findings with fingerprints or a fingerprints array');
  return new Set(fingerprints);
}

export async function loadBaseline(file: string): Promise<Set<string>> {
  const info = await stat(file).catch(() => null);
  if (!info?.isFile()) throw new UsageError(`Baseline file does not exist: ${file}`);
  if (info.size > MAX_BASELINE_BYTES) throw new UsageError(`Baseline exceeds ${MAX_BASELINE_BYTES} bytes: ${file}`);
  return parseBaseline(await readFile(file, 'utf8'));
}

function nulPaths(stdout: string): string[] {
  return stdout.split('\0').filter(Boolean).map((file) => file.replaceAll('\\', '/'));
}

export async function changedFilesSince(root: string, ref: string, exec: ExecFn, signal?: AbortSignal): Promise<Set<string>> {
  if (!ref || ref.startsWith('-') || /[\0\r\n]/.test(ref)) throw new UsageError('Invalid Git ref for --changed-since');
  const options = { cwd: root, timeoutMs: 30_000, ...(signal ? { signal } : {}) };
  const diff = await exec('git', ['diff', '--relative', '--name-only', '-z', '--diff-filter=ACMR', ref, '--'], options);
  if (diff.code !== 0) throw new UsageError(`Cannot compare changed files with Git ref "${ref}"`);
  const untracked = await exec('git', ['ls-files', '--others', '--exclude-standard', '-z'], options);
  if (untracked.code !== 0) throw new UsageError('Cannot list untracked files for --changed-since');
  return new Set([...nulPaths(diff.stdout), ...nulPaths(untracked.stdout)]);
}

export function applyFindingScope(report: Report, scope: FindingScope): Report {
  let baselineSuppressed = 0;
  let unchangedSuppressed = 0;
  const findings = report.findings.filter((finding) => {
    if (scope.baseline?.fingerprints.has(finding.fingerprint)) {
      baselineSuppressed++;
      return false;
    }
    if (scope.changed && (!finding.file || !scope.changed.files.has(finding.file))) {
      unchangedSuppressed++;
      return false;
    }
    return true;
  });
  const passed = !findings.some((finding) => meetsThreshold(finding.severity, report.failOn));
  const status = !passed ? 'failed' : report.scanners.some((scanner) => scanner.incomplete) ? 'incomplete' : 'passed';
  return {
    ...report,
    passed,
    status,
    summary: { ...countBySeverity(findings), total: findings.length, ignored: report.summary.ignored },
    findings,
    scope: {
      ...(scope.baseline ? { baseline: scope.baseline.label } : {}),
      ...(scope.changed ? { changedSince: scope.changed.ref, changedFiles: scope.changed.files.size } : {}),
      baselineSuppressed,
      unchangedSuppressed,
    },
  };
}

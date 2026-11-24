import { describe, expect, it } from 'vitest';
import { withFingerprint } from '../../src/core/fingerprint.js';
import { applyFindingScope, changedFilesSince, parseBaseline } from '../../src/core/scope.js';
import type { Finding, Report } from '../../src/core/types.js';

function finding(file: string, ruleId: string, severity: Finding['severity'] = 'high'): Finding {
  return withFingerprint({ scanner: 'workflow-audit', ruleId, title: ruleId, severity, category: 'workflow', file, line: 1, message: ruleId, references: [] });
}

const oldFinding = finding('legacy.yml', 'legacy');
const changedFinding = finding('changed.yml', 'new-critical', 'critical');
const unchangedFinding = finding('unchanged.yml', 'new-high');

function report(): Report {
  return {
    schemaVersion: 1, tool: { name: 'mikeops-guard', version: '1.0.0' }, target: '/repo',
    startedAt: '2026-01-01T00:00:00.000Z', finishedAt: '2026-01-01T00:00:01.000Z', durationMs: 1000,
    failOn: 'high', passed: false, status: 'failed',
    summary: { critical: 1, high: 2, medium: 0, low: 0, info: 0, total: 3, ignored: 2 },
    scanners: [{ scanner: 'workflow-audit', title: 'Workflow', status: 'ok', durationMs: 1, findingCount: 3, incomplete: false }],
    findings: [oldFinding, changedFinding, unchangedFinding],
  };
}

describe('finding scope', () => {
  it('accepts a prior MikeOps report as a fingerprint baseline', () => {
    expect(parseBaseline(JSON.stringify(report()))).toEqual(new Set([oldFinding.fingerprint, changedFinding.fingerprint, unchangedFinding.fingerprint]));
  });

  it('keeps only new findings in changed files and records each suppression reason', () => {
    const scoped = applyFindingScope(report(), {
      baseline: { label: 'baseline.json', fingerprints: new Set([oldFinding.fingerprint]) },
      changed: { ref: 'main', files: new Set(['legacy.yml', 'changed.yml']) },
    });
    expect(scoped.findings).toEqual([changedFinding]);
    expect(scoped.summary).toMatchObject({ critical: 1, high: 0, total: 1, ignored: 2 });
    expect(scoped.scope).toEqual({ baseline: 'baseline.json', changedSince: 'main', changedFiles: 2, baselineSuppressed: 1, unchangedSuppressed: 1 });
    expect(scoped.status).toBe('failed');
  });

  it('preserves incomplete coverage when scoping removes every finding', () => {
    const input = report();
    input.scanners[0] = { ...input.scanners[0]!, status: 'failed', incomplete: true };
    const scoped = applyFindingScope(input, { changed: { ref: 'main', files: new Set() } });
    expect(scoped).toMatchObject({ passed: true, status: 'incomplete', summary: { total: 0 } });
  });

  it('collects committed, staged, unstaged and untracked paths without a shell', async () => {
    const calls: Array<{ command: string; args: readonly string[] }> = [];
    const exec = (command: string, args: readonly string[]) => {
      calls.push({ command, args });
      return Promise.resolve(calls.length === 1
        ? { code: 0, stdout: 'src/a.ts\0src/b.ts\0', stderr: '' }
        : { code: 0, stdout: 'new file.ts\0src/a.ts\0', stderr: '' });
    };
    const files = await changedFilesSince('/repo', 'origin/main', exec);
    expect(files).toEqual(new Set(['src/a.ts', 'src/b.ts', 'new file.ts']));
    expect(calls).toEqual([
      { command: 'git', args: ['diff', '--relative', '--name-only', '-z', '--diff-filter=ACMR', 'origin/main', '--'] },
      { command: 'git', args: ['ls-files', '--others', '--exclude-standard', '-z'] },
    ]);
  });
});

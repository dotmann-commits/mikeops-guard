import { describe, expect, it } from 'vitest';
import { withFingerprint } from '../../src/core/fingerprint.js';
import type { Report } from '../../src/core/types.js';
import { renderSarif } from '../../src/report/sarif.js';

const report: Report = {
  schemaVersion: 1,
  tool: { name: 'mikeops-guard', version: '1.2.3' },
  target: '/tmp/private/repo',
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:00:01.000Z',
  durationMs: 1000,
  failOn: 'high',
  passed: false,
  status: 'failed',
  summary: { critical: 0, high: 1, medium: 0, low: 1, info: 0, total: 2, ignored: 0 },
  scanners: [{ scanner: 'workflow-audit', title: 'Audit', status: 'ok', durationMs: 5, findingCount: 2, incomplete: false }],
  findings: [
    withFingerprint({
      scanner: 'workflow-audit', ruleId: 'script-injection', title: 'Untrusted input', severity: 'high', category: 'workflow',
      file: '.github/workflows/ci.yml', line: 9, message: 'Issue title reaches shell.', remediation: 'Use an environment variable.', references: ['https://example.com/rule'],
    }),
    withFingerprint({
      scanner: 'workflow-audit', ruleId: 'repository-policy', title: 'Repository issue', severity: 'low', category: 'workflow',
      message: 'Repository-level finding.', references: [],
    }),
  ],
};

describe('renderSarif', () => {
  it('emits GitHub-compatible SARIF 2.1.0 with stable rule and result fingerprints', () => {
    const sarif = JSON.parse(renderSarif(report)) as {
      version: string;
      $schema: string;
      runs: Array<{
        tool: { driver: { name: string; version: string; rules: unknown[] } };
        results: Array<{ locations?: unknown[] }>;
      }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);
    const run = sarif.runs.at(0);
    expect(run?.tool.driver).toMatchObject({ name: 'MikeOps Guard', version: '1.2.3' });
    expect(run?.tool.driver.rules.at(0)).toMatchObject({
      id: 'workflow-audit/script-injection',
      properties: { 'security-severity': '8.0' },
    });
    expect(run?.results.at(0)).toMatchObject({
      ruleId: 'workflow-audit/script-injection',
      level: 'error',
      partialFingerprints: { 'mikeopsGuardFingerprint/v1': report.findings[0]?.fingerprint },
      locations: [{ physicalLocation: { artifactLocation: { uri: '.github/workflows/ci.yml' }, region: { startLine: 9 } } }],
    });
    expect(run?.results.at(1)?.locations).toBeUndefined();
    expect(renderSarif(report)).not.toContain('/tmp/private/repo');
  });
});

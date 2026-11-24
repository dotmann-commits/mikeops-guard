import { describe, expect, it } from 'vitest';
import { withFingerprint } from '../../src/core/fingerprint.js';
import type { Report } from '../../src/core/types.js';
import { renderMarkdown } from '../../src/report/markdown.js';

const report: Report = {
  schemaVersion: 1,
  tool: { name: 'mikeops-guard', version: '1.2.3' },
  target: '/repo', startedAt: '2026-01-01T00:00:00.000Z', finishedAt: '2026-01-01T00:00:01.000Z', durationMs: 1000,
  failOn: 'high', passed: false, status: 'failed',
  summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1, ignored: 0 },
  scanners: [{ scanner: 'workflow-audit', title: 'Audit', status: 'ok', durationMs: 5, findingCount: 1, incomplete: false }],
  findings: [withFingerprint({
    scanner: 'workflow-audit', ruleId: 'script-injection', title: '<unsafe>|title', severity: 'high', category: 'workflow',
    file: '.github/workflows/ci.yml', line: 9, message: 'message', remediation: 'Use env | quoting.', references: [],
  })],
};

describe('renderMarkdown', () => {
  it('renders an escaped GitHub step-summary table and verdict', () => {
    const markdown = renderMarkdown(report);
    expect(markdown).toContain('# MikeOps Guard — Failed');
    expect(markdown).toContain('| Critical | High | Medium | Low | Info | Ignored |');
    expect(markdown).toContain('`.github/workflows/ci.yml:9`');
    expect(markdown).toContain('&lt;unsafe&gt;\\|title');
    expect(markdown).toContain('Use env \\| quoting.');
    expect(markdown).not.toContain('<unsafe>');
  });
});

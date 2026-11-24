import { describe, expect, it } from 'vitest';
import { withFingerprint } from '../../src/core/fingerprint.js';
import type { Finding, Report, ScannerId } from '../../src/core/types.js';
import { correlateAttackPaths } from '../../src/report/attack-paths.js';
import { renderConsole } from '../../src/report/console.js';
import { renderHtml } from '../../src/report/html.js';

function finding(scanner: ScannerId, ruleId: string, file: string, severity: Finding['severity'] = 'high'): Finding {
  return withFingerprint({ scanner, ruleId, title: ruleId, severity, category: scanner === 'workflow-audit' ? 'workflow' : scanner === 'gitleaks' ? 'secret' : 'application', file, line: 1, message: ruleId, references: [] });
}

const findings = [
  finding('ai-supply-chain', 'invisible-unicode-control', '.cursorrules'),
  finding('workflow-audit', 'script-injection', '.github/workflows/ci.yml'),
  finding('gitleaks', 'generic-api-key', '.env', 'critical'),
  finding('app-security', 'supabase-table-without-rls', 'supabase/001.sql'),
];

const report: Report = {
  schemaVersion: 1, tool: { name: 'mikeops-guard', version: '1.2.3' }, target: '/repo',
  startedAt: '2026-01-01T00:00:00.000Z', finishedAt: '2026-01-01T00:00:01.000Z', durationMs: 1000,
  failOn: 'high', passed: false, status: 'failed',
  summary: { critical: 1, high: 3, medium: 0, low: 0, info: 0, total: 4, ignored: 0 },
  scanners: [], findings,
};

describe('attack-path correlation', () => {
  it('builds distinct credential and application blast-radius paths from cross-layer evidence', () => {
    const paths = correlateAttackPaths(findings);
    expect(paths.map((path) => path.id)).toEqual(['agent-ci-secret', 'agent-ci-application']);
    expect(paths[0]?.severity).toBe('critical');
    expect(paths[0]?.stages.map((stage) => stage.scanner)).toEqual(['ai-supply-chain', 'workflow-audit', 'gitleaks']);
    expect(paths[1]?.stages.map((stage) => stage.scanner)).toEqual(['ai-supply-chain', 'workflow-audit', 'app-security']);
  });

  it('shows correlated paths in terminal and HTML reports', () => {
    expect(renderConsole(report, { color: false, maxFindings: 0 })).toContain('Potential attack paths');
    const html = renderHtml(report);
    expect(html).toContain('Potential attack paths');
    expect(html).toContain('AI toolchain compromise can reach CI credentials');
  });
});

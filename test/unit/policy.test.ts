import { describe, expect, it } from 'vitest';
import { parseConfig } from '../../src/config/load.js';
import { withFingerprint } from '../../src/core/fingerprint.js';
import { applyPolicy, exitCodeFor, meetsThreshold } from '../../src/core/policy.js';
import type { Finding, Report } from '../../src/core/types.js';

const finding = (overrides: Partial<Finding> = {}): Finding =>
  withFingerprint({
    scanner: 'hadolint',
    ruleId: 'DL3008',
    title: 't',
    severity: 'medium',
    category: 'container',
    file: 'Dockerfile',
    line: 3,
    message: 'm',
    references: [],
    ...overrides,
  });

describe('meetsThreshold', () => {
  it('compares by rank and never fails on "none"', () => {
    expect(meetsThreshold('high', 'high')).toBe(true);
    expect(meetsThreshold('medium', 'high')).toBe(false);
    expect(meetsThreshold('critical', 'none')).toBe(false);
  });
});

describe('applyPolicy', () => {
  it('ignores by rule, scanner:rule, path glob and fingerprint', () => {
    const a = finding();
    const b = finding({ ruleId: 'DL3007', file: 'docker/app.Dockerfile' });
    const c = finding({ scanner: 'gitleaks', ruleId: 'aws-key', severity: 'critical', category: 'secret' });
    const d = finding({ ruleId: 'DL4000' });
    const config = parseConfig(`
ignore:
  - rule: DL3008
  - rule: DL3007
    path: docker/**
  - rule: gitleaks:aws-key
  - rule: ${d.fingerprint}
`);
    expect(applyPolicy([a, b, c, d], config)).toEqual({ kept: [], ignored: 4 });
  });

  it('does not ignore when the path does not match', () => {
    const config = parseConfig('ignore:\n  - rule: DL3008\n    path: other/**\n');
    expect(applyPolicy([finding()], config).kept).toHaveLength(1);
  });

  it('applies severity overrides and excludes, then sorts by severity', () => {
    const config = parseConfig('severityOverrides:\n  DL3008: critical\nexclude: ["vendor/**"]\n');
    const { kept, ignored } = applyPolicy(
      [finding({ ruleId: 'X', severity: 'low' }), finding(), finding({ file: 'vendor/Dockerfile' })],
      config,
    );
    expect(kept.map((f) => [f.ruleId, f.severity])).toEqual([
      ['DL3008', 'critical'],
      ['X', 'low'],
    ]);
    expect(ignored).toBe(1);
  });
});

describe('exitCodeFor', () => {
  const report = (passed: boolean, failed: boolean): Report =>
    ({
      passed,
      scanners: [{ scanner: 'hadolint', title: 'x', status: failed ? 'failed' : 'ok', durationMs: 0, findingCount: 0 }],
    }) as unknown as Report;

  it('returns 1 for a policy failure even when a scanner also failed', () => {
    expect(exitCodeFor(report(false, true))).toBe(1);
    expect(exitCodeFor(report(true, true))).toBe(3);
    expect(exitCodeFor(report(true, false))).toBe(0);
  });
});

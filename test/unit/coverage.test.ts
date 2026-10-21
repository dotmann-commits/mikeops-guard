import { describe, expect, it } from 'vitest';
import { configSchema, type ConfigInput } from '../../src/config/schema.js';
import { EXIT_CODES } from '../../src/core/exit-codes.js';
import { exitCodeFor } from '../../src/core/policy.js';
import { runScan } from '../../src/core/run.js';
import type { Scanner } from '../../src/core/scanner.js';
import type { NewFinding } from '../../src/core/types.js';

const finding = (severity: NewFinding['severity']): NewFinding => ({
  scanner: 'workflow-audit',
  ruleId: 'r',
  title: 't',
  severity,
  category: 'workflow',
  message: 'm',
  references: [],
});

const builtIn = (id: Scanner['id'], findings: NewFinding[] = [], skip: string | null = null): Scanner => ({
  id,
  title: id,
  category: 'workflow',
  tool: () => null,
  skipReason: () => skip,
  run: () => Promise.resolve(findings),
});

const external: Scanner = {
  id: 'gitleaks',
  title: 'gitleaks',
  category: 'secret',
  tool: () => 'gitleaks',
  skipReason: () => null,
  run: () => Promise.resolve([]),
};

async function scan(scanners: Scanner[], config: ConfigInput = {}, installed = false) {
  const report = await runScan({
    root: process.cwd(),
    config: configSchema.parse(config),
    scanners,
    exec: () => Promise.reject(new Error('not used')),
    resolveBinary: () => (installed ? '/usr/bin/true' : null),
    toolVersion: '0.0.0',
  });
  return { report, code: exitCodeFor(report) };
}

describe('scan coverage', () => {
  it('passes when every scanner ran or had nothing to check', async () => {
    const { report, code } = await scan([builtIn('workflow-audit'), builtIn('hadolint', [], 'no Dockerfiles found')]);
    expect(report.status).toBe('passed');
    expect(report.scanners.map((s) => s.incomplete)).toEqual([false, false]);
    expect(code).toBe(EXIT_CODES.pass);
  });

  it('is incomplete, not passed, when an optional tool is missing', async () => {
    const { report, code } = await scan([builtIn('workflow-audit'), external]);
    expect(report.passed).toBe(true); // policy result, unchanged meaning
    expect(report.status).toBe('incomplete');
    expect(report.scanners.find((s) => s.scanner === 'gitleaks')).toMatchObject({ status: 'skipped', incomplete: true });
    expect(code).toBe(EXIT_CODES.pass);
  });

  it('fails with exit code 3 when a required tool is missing', async () => {
    const { report, code } = await scan([builtIn('workflow-audit'), external], { requireTools: true });
    expect(report.status).toBe('incomplete');
    expect(report.scanners.find((s) => s.scanner === 'gitleaks')).toMatchObject({ status: 'failed', incomplete: true });
    expect(code).toBe(EXIT_CODES.scannerFailed);
  });

  it('reports scanners disabled by the config instead of hiding them', async () => {
    const { report } = await scan([builtIn('workflow-audit'), builtIn('hadolint')], { scanners: { hadolint: { enabled: false } } });
    expect(report.status).toBe('incomplete');
    expect(report.scanners.map((s) => s.scanner)).toEqual(['workflow-audit', 'hadolint']);
    expect(report.scanners[1]).toMatchObject({ status: 'skipped', incomplete: true });
  });

  it('marks a crashed scanner as incomplete and a policy failure as failed', async () => {
    const crashing: Scanner = { ...builtIn('hadolint'), run: () => Promise.reject(new Error('boom')) };
    const crashed = await scan([builtIn('workflow-audit'), crashing]);
    expect(crashed.report.status).toBe('incomplete');
    expect(crashed.code).toBe(EXIT_CODES.scannerFailed);
    const failed = await scan([builtIn('workflow-audit', [finding('critical')]), crashing]);
    expect(failed.report.status).toBe('failed');
    expect(failed.code).toBe(EXIT_CODES.policyFailed);
  });
});

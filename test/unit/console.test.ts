import { describe, expect, it } from 'vitest';
import { withFingerprint } from '../../src/core/fingerprint.js';
import type { Report } from '../../src/core/types.js';
import { renderConsole } from '../../src/report/console.js';
import { terminalSafe } from '../../src/report/terminal.js';

const ESC = '\x1b';
const RLO = '\u202E'; // right-to-left override, the "Trojan Source" character
const hostile = `${ESC}[2J${ESC}]8;;https://evil.example${ESC}\\click${ESC}]8;;${ESC}\\\rPASSED${RLO}gnp.exe`;
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\x00-\x08\x0B-\x1F\x7F-\x9F\u202A-\u202E\u2066-\u2069]/;
// eslint-disable-next-line no-control-regex
const GUARD_COLOUR = /\x1b\[[0-9;]*m/g;

const report: Report = {
  schemaVersion: 1,
  tool: { name: 'mikeops-guard', version: '0.0.0' },
  target: `/tmp/repo${ESC}[31m`,
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:00:01.000Z',
  durationMs: 1000,
  failOn: 'high',
  passed: false,
  status: 'failed',
  summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1, ignored: 0 },
  scanners: [
    { scanner: 'hadolint', title: 'Dockerfile lint', status: 'failed', durationMs: 5, findingCount: 0, incomplete: true, reason: `boom ${hostile}` },
  ],
  findings: [
    withFingerprint({
      scanner: 'workflow-audit',
      ruleId: `rule${ESC}[8m`,
      title: `Title ${hostile}`,
      severity: 'high',
      category: 'workflow',
      file: `.github/workflows/${hostile}.yml`,
      message: `Message ${hostile}`,
      remediation: `Fix ${hostile}`,
      explanation: `Risk: ${hostile}\nFix: line two`,
      references: [],
    }),
  ],
};

describe('terminal safety', () => {
  it('removes escape sequences, carriage returns and bidi overrides from untrusted text', () => {
    expect(terminalSafe(`a${ESC}[2Jb\rc${RLO}d\te\nf`)).toBe('a[2Jbcd\te\nf');
  });

  it('prints no control characters from scanners or the repository, with or without colour', () => {
    const plain = renderConsole(report, { color: false, maxFindings: 10 });
    expect(plain).not.toMatch(UNSAFE);
    expect(plain).toContain('Message [2J]8;;https://evil.example\\click]8;;\\PASSEDgnp.exe'); // visible, inert
    const coloured = renderConsole(report, { color: true, maxFindings: 10 });
    const own = coloured.match(GUARD_COLOUR) ?? [];
    expect(coloured.split(ESC).length - 1).toBe(own.length); // only Guard's own colour codes remain
    expect(coloured).not.toContain('\r');
  });
});

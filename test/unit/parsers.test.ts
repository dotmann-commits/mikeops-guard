import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ScannerError } from '../../src/core/errors.js';
import { parseActionlint } from '../../src/scanners/actionlint.js';
import { parseOsv, parseTrivyFs } from '../../src/scanners/dependencies.js';
import { parseGitleaks } from '../../src/scanners/gitleaks.js';
import { parseHadolint } from '../../src/scanners/hadolint.js';
import { parseTrivyConfig } from '../../src/scanners/trivy-config.js';
import { relativeToRoot, severityFromCvss } from '../../src/scanners/shared.js';

/** Every fixture here is unedited output captured from the real tool. */
const fixture = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, '../fixtures/tool-output', name), 'utf8');

describe('parseHadolint', () => {
  it('maps levels and builds wiki links', () => {
    const findings = parseHadolint(fixture('hadolint.json'), '/repo');
    expect(findings).toHaveLength(6);
    const add = findings.find((f) => f.ruleId === 'DL3020');
    expect(add).toMatchObject({ severity: 'high', line: 3, file: 'docker/app.Dockerfile', title: 'Use COPY instead of ADD for files and folders' });
    expect(add?.references).toEqual(['https://github.com/hadolint/hadolint/wiki/DL3020']);
  });

  it('returns nothing for empty output', () => {
    expect(parseHadolint('', '/repo')).toEqual([]);
  });
});

describe('parseTrivyConfig', () => {
  it('keeps failed checks with resolution and line', () => {
    const findings = parseTrivyConfig(fixture('trivy-config.json'), '/demo');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.file === 'docker/app.Dockerfile' && f.category === 'container')).toBe(true);
    expect(findings.every((f) => f.remediation)).toBe(true);
    expect(findings.some((f) => f.ruleId.startsWith('DS'))).toBe(true);
  });
});

describe('parseActionlint', () => {
  it('maps kinds and relative paths', () => {
    const [first] = parseActionlint(fixture('actionlint.json'), '/demo');
    expect(first).toMatchObject({ ruleId: 'actionlint-expression', severity: 'medium', file: '.github/workflows/pr-preview.yml', line: 14 });
  });

  it('accepts "null" when there are no errors', () => {
    expect(parseActionlint('null\n', '/demo')).toEqual([]);
  });
});

describe('parseGitleaks', () => {
  const findings = parseGitleaks(fixture('gitleaks.json'), '/repo');

  it('reports a critical secret with commit context', () => {
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'github-pat', severity: 'critical', file: 'deploy.sh', line: 1 });
    expect(findings[0]?.message).toMatch(/commit [0-9a-f]{12}/);
  });

  it('never carries the Secret or Match fields into a finding', () => {
    expect(JSON.stringify(findings)).not.toContain('REDACTED');
  });
});

describe('parseOsv', () => {
  const findings = parseOsv(fixture('osv.json'), '/demo');

  it('creates one finding per alias group, not per alias', () => {
    const raw = JSON.parse(fixture('osv.json')) as { results: { packages: { groups: unknown[] }[] }[] };
    expect(findings).toHaveLength(raw.results[0]?.packages[0]?.groups.length ?? -1);
  });

  it('prefers the CVE id and a real version as the fix', () => {
    const first = findings.find((f) => f.ruleId === 'CVE-2014-1402');
    expect(first).toMatchObject({ severity: 'high', file: 'requirements.txt', remediation: 'Upgrade jinja2 to 2.7.2 or later.' });
    for (const f of findings) {
      expect(f.remediation).not.toMatch(/to [0-9a-f]{40}/);
    }
  });
});

describe('parseTrivyFs', () => {
  it('maps vulnerabilities with fixed versions', () => {
    const findings = parseTrivyFs(fixture('trivy-fs.json'), '/demo');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.file === 'requirements.txt' && f.title.startsWith('jinja2@2.4.1'))).toBe(true);
  });
});

describe('shared helpers', () => {
  it('uses CVSS v3 bands', () => {
    expect([9.8, 7, 6.9, 0.1, 0].map(severityFromCvss)).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });

  it('rejects output that is not JSON or has the wrong shape', () => {
    expect(() => parseHadolint('Error: something broke', '/r')).toThrow(ScannerError);
    expect(() => parseHadolint('{"not":"an array"}', '/r')).toThrow(/did not match/);
  });
});

describe('relativeToRoot', () => {
  it('reports a file inside a root that was given through a symbolic link as a path inside the root', () => {
    // Reproduces macOS, where /tmp and /var link to /private/...: a scanner reports the real path of the file.
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'guard-link-')));
    try {
      const realRoot = path.join(base, 'real');
      const linkRoot = path.join(base, 'link');
      mkdirSync(realRoot);
      writeFileSync(path.join(realRoot, 'requirements.txt'), 'jinja2==2.4.1\n');
      writeFileSync(path.join(base, 'outside.txt'), '');
      symlinkSync(realRoot, linkRoot, 'dir');
      expect(relativeToRoot(linkRoot, path.join(realRoot, 'requirements.txt'))).toBe('requirements.txt');
      expect(relativeToRoot(linkRoot, 'docker/Dockerfile')).toBe('docker/Dockerfile');
      expect(relativeToRoot(linkRoot, path.join(base, 'outside.txt'))).toBe('../outside.txt'); // really outside stays outside
      expect(relativeToRoot(linkRoot, '/nowhere/gone.txt')).toMatch(/^\.\.\//); // unresolvable keeps the plain result
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
});

import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { withFingerprint } from '../../src/core/fingerprint.js';
import type { Report } from '../../src/core/types.js';
import { escapeHtml, safeUrl } from '../../src/report/escape.js';
import { renderHtml } from '../../src/report/html.js';

const report: Report = {
  schemaVersion: 1,
  tool: { name: 'mikeops-guard', version: '0.0.0' },
  target: '/tmp/<repo>',
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:00:01.000Z',
  durationMs: 1000,
  failOn: 'high',
  passed: false,
  status: 'failed',
  summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1, ignored: 0 },
  scanners: [{ scanner: 'workflow-audit', title: 'Audit', status: 'ok', durationMs: 5, findingCount: 1, incomplete: false }],
  findings: [
    withFingerprint({
      scanner: 'workflow-audit',
      ruleId: 'script-injection',
      title: '<img src=x onerror=alert(1)>',
      severity: 'high',
      category: 'workflow',
      file: '.github/workflows/"x".yml',
      line: 4,
      message: '${{ github.event.issue.title }} & more',
      references: ['javascript:alert(1)', 'https://example.com/a?b=1&c=2'],
    }),
  ],
};

describe('renderHtml', () => {
  const html = renderHtml(report);

  it('escapes untrusted values from scanners and file names', () => {
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).toContain('&quot;x&quot;.yml:4');
    expect(html).toContain('/tmp/&lt;repo&gt;');
  });

  it('only links http(s) references', () => {
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain('href="https://example.com/a?b=1&amp;c=2"');
    expect(html).toContain('rel="noopener noreferrer"');
  });

  it('is self-contained with a strict CSP', () => {
    expect(html).toContain("default-src 'none'");
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+stylesheet/);
  });
});

describe('escape helpers', () => {
  it('escapes all five HTML special characters', () => {
    expect(escapeHtml(`<a href="x">'&'</a>`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
  });

  it('rejects non-web URLs', () => {
    expect(safeUrl('data:text/html,hi')).toBeNull();
    expect(safeUrl('not a url')).toBeNull();
    expect(safeUrl('https://osv.dev/x')).toBe('https://osv.dev/x');
  });

  it('allows only its own script, by hash, and no other inline script', () => {
    const html = renderHtml(report);
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] ?? '';
    const script = /<script>([\s\S]*?)<\/script>/.exec(html)?.[1] ?? '';
    const expected = `'sha256-${createHash('sha256').update(script).digest('base64')}'`;
    const scriptSrc = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('script-src')) ?? '';
    expect(scriptSrc).toBe(`script-src ${expected}`);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("base-uri 'none'");
  });

  it('labels an incomplete scan as incomplete, never as passed', () => {
    const incomplete = renderHtml({ ...report, passed: true, status: 'incomplete', findings: [],
      scanners: [{ scanner: 'gitleaks', title: 'Secret detection', status: 'skipped', durationMs: 0, findingCount: 0, incomplete: true, reason: 'gitleaks is not installed' }] });
    expect(incomplete).toContain('verdict warn">Incomplete');
    expect(incomplete).not.toContain('verdict pass');
    expect(incomplete).toContain('Incomplete scan:');
  });
});

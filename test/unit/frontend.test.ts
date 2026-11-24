import { describe, expect, it } from 'vitest';
import { sourceFindings } from '../../src/scanners/app-security/frontend.js';

const browser = { browser: true, clientDirective: false };

describe('frontend finding locations', () => {
  it('does not report public frontend variables outside a browser application', () => {
    expect(sourceFindings('src/cli.ts', 'process.env.VITE_SECRET;', { browser: false, clientDirective: false })).toEqual([]);
  });

  it.each(['\n', '\r\n'])('keeps reference order and lines with %j line endings', (newline) => {
    const source = [
      'process.env.VITE_SECRET; import.meta.env.PUBLIC_PASSWORD;',
      '',
      '// unrelated text',
      'const key = serviceRoleKey;',
      'process.env.NEXT_PUBLIC_SECRET;',
      'import.meta.env.VITE_SERVICE_ROLE_KEY;',
    ].join(newline);

    const findings = sourceFindings('src/client.ts', source, browser);

    expect(findings.map((f) => [f.ruleId, f.line])).toEqual([
      ['public-env-secret', 1],
      ['public-env-secret', 1],
      ['public-env-secret', 5],
      ['public-env-secret', 6],
      ['service-role-in-frontend', 4],
    ]);
  });

  it.each([
    ['service_role_key\n\nprocess.env.VITE_SECRET', [3, 1]],
    ['process.env.VITE_SECRET\n\nservice_role_key', [1, 3]],
    ['\n\nservice_role_key', [3]],
  ] as const)('locates the service role independently of public references in %j', (source, lines) => {
    expect(sourceFindings('src/client.ts', source, browser).map((f) => f.line)).toEqual(lines);
  });

  it('resets line counters between files', () => {
    sourceFindings('src/first.ts', '\n'.repeat(20) + 'process.env.VITE_SECRET; serviceRoleKey', browser);

    expect(sourceFindings('src/second.ts', 'process.env.VITE_SECRET; serviceRoleKey', browser).map((f) => f.line))
      .toEqual([1, 1]);
  });

  it('keeps exact locations for thousands of public references', () => {
    const count = 4000;
    const findings = sourceFindings('src/client.ts', 'process.env.VITE_SECRET;\n'.repeat(count), browser);

    expect(findings).toHaveLength(count);
    expect(findings.map((f) => f.line)).toEqual(Array.from({ length: count }, (_, i) => i + 1));
  });
});

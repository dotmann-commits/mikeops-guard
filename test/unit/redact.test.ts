import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { configSchema } from '../../src/config/schema.js';
import { REDACTED, redactSecrets } from '../../src/core/redact.js';
import { runScan } from '../../src/core/run.js';
import type { Scanner } from '../../src/core/scanner.js';
import { explainFindings, OllamaClient, type FetchFn } from '../../src/explain/ollama.js';
import { renderConsole } from '../../src/report/console.js';
import { renderHtml } from '../../src/report/html.js';
import { renderJson } from '../../src/report/json.js';

// Built at run time from parts, so no credential-shaped string is committed (Guard scans its own repository).
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const rand = (n: number, alphabet = ALNUM): string => [...randomBytes(n)].map((b) => alphabet[b % alphabet.length]).join('');
const tokens = {
  github: ['gh', 'p_', rand(36)].join(''),
  githubPat: ['github', '_pat_', rand(82)].join(''),
  aws: ['AK', 'IA', rand(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')].join(''),
  slack: ['xo', 'xb-', rand(24)].join(''),
  stripe: ['sk', '_live_', rand(24)].join(''),
  google: ['AI', 'za', rand(35)].join(''),
  openai: ['sk', '-proj-', rand(40)].join(''),
  jwt: ['ey', 'J', rand(20), '.ey', 'J', rand(30), '.', rand(30)].join(''),
  key: ['-----BEGIN ', 'RSA PRIVATE KEY-----\n', rand(64), '\n-----END RSA PRIVATE KEY-----'].join(''),
};
const assignment = { text: `DB_PASSWORD="${rand(20)}"`, value: '' };
assignment.value = assignment.text.slice(13, -1);

describe('redactSecrets', () => {
  it('removes every supported credential format', () => {
    for (const [name, token] of Object.entries(tokens)) {
      const out = redactSecrets(`found ${token} in config`);
      expect(out, name).not.toContain(token);
      expect(out, name).toContain(REDACTED);
    }
  });

  it('redacts the value of a secret-named assignment and keeps the key readable', () => {
    const out = redactSecrets(`env: ${assignment.text}`);
    expect(out).not.toContain(assignment.value);
    expect(out).toContain('DB_PASSWORD="[REDACTED]"');
  });

  it('leaves ordinary text and GitHub expressions alone', () => {
    const text = 'Job "build" expands ${{ secrets.GITHUB_TOKEN }} and sets permissions: write-all. token: ${{ github.token }}';
    expect(redactSecrets(text)).toBe(text);
  });
});

describe('reports never contain credential values', () => {
  const leaky: Scanner = {
    id: 'workflow-audit',
    title: 'Leaky scanner',
    category: 'workflow',
    tool: () => null,
    skipReason: () => null,
    run: () =>
      Promise.resolve([
        {
          scanner: 'workflow-audit',
          ruleId: 'quoted-config',
          title: `Hardcoded ${tokens.github}`,
          severity: 'high',
          category: 'workflow',
          file: 'ci.yml',
          message: `env: API_TOKEN: ${tokens.slack} and ${assignment.text}`,
          remediation: `Rotate ${tokens.aws}`,
          references: [],
        },
      ]),
  };
  const failing: Scanner = {
    id: 'hadolint',
    title: 'Failing scanner',
    category: 'container',
    tool: () => null,
    skipReason: () => null,
    run: () => Promise.reject(new Error(`tool crashed while reading ${tokens.stripe}`)),
  };

  it('redacts finding text and scanner errors in console, JSON and HTML', async () => {
    const report = await runScan({
      root: process.cwd(),
      config: configSchema.parse({}),
      scanners: [leaky, failing],
      exec: () => Promise.reject(new Error('not used')),
      resolveBinary: () => null,
      toolVersion: '0.0.0',
    });
    const outputs = [renderJson(report), renderHtml(report), renderConsole(report, { color: false, maxFindings: 10 })];
    for (const output of outputs) {
      for (const secret of [tokens.github, tokens.slack, tokens.aws, tokens.stripe, assignment.value]) {
        expect(output).not.toContain(secret);
      }
      expect(output).toContain(REDACTED);
    }
  });

  it('sends nothing credential-shaped to the model and redacts what it returns', async () => {
    const prompts: string[] = [];
    const fakeOllama: FetchFn = (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === '/api/tags') return Promise.resolve(new Response(JSON.stringify({ models: [{ name: 'm:latest' }] })));
      prompts.push(typeof init?.body === 'string' ? init.body : '');
      return Promise.resolve(new Response(JSON.stringify({ response: `Risk: leaked ${tokens.google}. Fix: rotate.` })));
    };
    const finding = {
      fingerprint: 'f',
      scanner: 'workflow-audit' as const,
      ruleId: 'r',
      title: 't',
      severity: 'high' as const,
      category: 'workflow' as const,
      message: `uses ${tokens.openai}`,
      references: [],
    };
    const client = new OllamaClient({ host: 'http://localhost:11434', model: 'm', timeoutMs: 1000, fetch: fakeOllama });
    const result = await explainFindings({ findings: [finding] } as never, client, 'm', 5);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain(REDACTED); // the prompt was really captured, and redacted
    expect(prompts.join()).not.toContain(tokens.openai);
    expect(result.findings[0]?.explanation).not.toContain(tokens.google);
    expect(result.findings[0]?.explanation).toContain(REDACTED);
  });
});

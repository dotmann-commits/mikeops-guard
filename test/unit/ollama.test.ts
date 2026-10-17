import { describe, expect, it } from 'vitest';
import { withFingerprint } from '../../src/core/fingerprint.js';
import type { Report } from '../../src/core/types.js';
import { buildPrompt, cleanExplanation, explainFindings, hasModel, OllamaClient, type FetchFn } from '../../src/explain/ollama.js';

const finding = (severity: 'high' | 'low', ruleId: string) =>
  withFingerprint({
    scanner: 'workflow-audit',
    ruleId,
    title: ruleId,
    severity,
    category: 'workflow',
    file: 'ci.yml',
    line: 1,
    message: 'details',
    references: [],
  });

const report = { findings: [finding('low', 'a'), finding('high', 'b')] } as unknown as Report;

/** Stand-in for the Ollama HTTP API, recording each request path. */
function fakeOllama(models: string[], calls: string[]): FetchFn {
  return (input) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    calls.push(url.pathname);
    const body = url.pathname === '/api/tags' ? { models: models.map((name) => ({ name })) } : { response: ' explained ' };
    return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
  };
}

describe('Ollama explainer', () => {
  it('matches model names the way the Ollama CLI does', () => {
    expect(hasModel(['llama3.2:latest'], 'llama3.2')).toBe(true);
    expect(hasModel(['llama3.2:3b'], 'llama3.2')).toBe(false);
  });

  it('explains the most severe findings first, within the limit', async () => {
    const calls: string[] = [];
    const client = new OllamaClient({ host: 'http://localhost:11434', model: 'm', timeoutMs: 1000, fetch: fakeOllama(['m:latest'], calls) });
    const result = await explainFindings(report, client, 'm', 1);
    expect(result.outcome).toEqual({ status: 'ok', model: 'm', explained: 1 });
    expect(result.findings.find((f) => f.ruleId === 'b')?.explanation).toBe('explained');
    expect(result.findings.find((f) => f.ruleId === 'a')?.explanation).toBeUndefined();
    expect(calls).toEqual(['/api/tags', '/api/generate']);
  });

  it('skips with a pull hint when the model is missing', async () => {
    const client = new OllamaClient({ host: 'http://localhost:11434', model: 'm', timeoutMs: 1000, fetch: fakeOllama([], []) });
    const result = await explainFindings(report, client, 'm', 5);
    expect(result.outcome.status).toBe('skipped');
    expect(result.outcome.reason).toContain('ollama pull m');
  });

  it('skips with a start hint when Ollama is down', async () => {
    const down: FetchFn = () => Promise.reject(new Error('ECONNREFUSED'));
    const client = new OllamaClient({ host: 'http://localhost:1', model: 'm', timeoutMs: 1000, fetch: down });
    const result = await explainFindings(report, client, 'm', 5);
    expect(result.outcome.reason).toContain('ollama serve');
  });

  it('never includes more than the finding metadata in the prompt', () => {
    expect(buildPrompt(finding('high', 'b'))).toBe(
      'Scanner: workflow-audit\nRule: b\nSeverity: high\nTitle: b\nLocation: ci.yml:1\nDetails: details',
    );
  });
});

describe('cleanExplanation', () => {
  it('removes preambles and markdown that small models add', () => {
    const raw = "Here's the review:\n\n**Risk**: tokens leak.\n\n\n**How it is exploited**: a fork PR.\n\n**Fix**: use `env:`.";
    expect(cleanExplanation(raw)).toBe('Risk: tokens leak.\n\nHow it is exploited: a fork PR.\n\nFix: use env:.');
  });
});

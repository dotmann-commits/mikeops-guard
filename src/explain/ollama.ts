import { z } from 'zod';
import { errorMessage } from '../core/errors.js';
import { redactSecrets } from '../core/redact.js';
import { severityRank } from '../core/policy.js';
import type { ExplainOutcome, Finding, Report } from '../core/types.js';

export type FetchFn = typeof fetch;

export interface OllamaOptions {
  host: string;
  model: string;
  timeoutMs: number;
  fetch?: FetchFn;
  /** Cancels in-flight requests when the user stops the run. */
  signal?: AbortSignal;
}

const tagsSchema = z.object({ models: z.array(z.object({ name: z.string() })) });
const generateSchema = z.object({ response: z.string() });

const SYSTEM_PROMPT = [
  'You are a senior DevSecOps engineer reviewing a security finding for a developer.',
  'Answer in plain English, in three short parts labelled Risk, How it is exploited, and Fix.',
  'Be specific to the finding. Keep the whole answer under 120 words. Do not invent file contents.',
  'Plain text only: no markdown, no introduction, start directly with "Risk:".',
].join(' ');

/** Small models still add markdown and preambles sometimes, so the answer is cleaned for terminal and HTML. */
export function cleanExplanation(text: string): string {
  const withoutMarkdown = text.replace(/\*\*|__|`/g, '').replace(/^#+\s*/gm, '');
  const riskStart = withoutMarkdown.search(/^Risk\b/im);
  const body = riskStart > 0 ? withoutMarkdown.slice(riskStart) : withoutMarkdown;
  return body.replace(/\n{3,}/g, '\n\n').trim();
}

export function buildPrompt(finding: Finding): string {
  return [
    `Scanner: ${finding.scanner}`,
    `Rule: ${finding.ruleId}`,
    `Severity: ${finding.severity}`,
    `Title: ${finding.title}`,
    `Location: ${finding.file ?? 'repository'}${finding.line ? `:${finding.line}` : ''}`,
    `Details: ${finding.message}`,
    finding.remediation ? `Suggested fix: ${finding.remediation}` : '',
  ]
    .filter(Boolean)
    .join('\n');
}

/** "llama3.2" matches "llama3.2:latest", the way the Ollama CLI resolves names. */
export function hasModel(installed: readonly string[], model: string): boolean {
  const wanted = model.includes(':') ? model : `${model}:latest`;
  return installed.some((name) => name === model || name === wanted);
}

export class OllamaClient {
  private readonly fetchFn: FetchFn;

  constructor(private readonly options: OllamaOptions) {
    this.fetchFn = options.fetch ?? fetch;
  }

  private async request(pathname: string, init?: RequestInit): Promise<unknown> {
    const url = new URL(pathname, this.options.host);
    const timeout = AbortSignal.timeout(this.options.timeoutMs);
    const signal = this.options.signal ? AbortSignal.any([timeout, this.options.signal]) : timeout;
    const response = await this.fetchFn(url, { ...init, signal });
    if (!response.ok) throw new Error(`Ollama returned HTTP ${response.status} for ${url.pathname}`);
    return response.json();
  }

  /** Returns null when ready, or a human-readable reason it is not. */
  async readiness(): Promise<string | null> {
    try {
      const tags = tagsSchema.parse(await this.request('/api/tags'));
      const names = tags.models.map((m) => m.name);
      if (!hasModel(names, this.options.model)) {
        return `model "${this.options.model}" is not pulled. Run: ollama pull ${this.options.model}`;
      }
      return null;
    } catch (error) {
      return `Ollama is not reachable at ${this.options.host} (${errorMessage(error)}). Start it with: ollama serve`;
    }
  }

  async explain(finding: Finding): Promise<string> {
    const body = JSON.stringify({
      model: this.options.model,
      system: SYSTEM_PROMPT,
      prompt: redactSecrets(buildPrompt(finding)), // nothing credential-shaped leaves for the model, even locally
      stream: false,
      options: { temperature: 0.2 },
    });
    const data = generateSchema.parse(
      await this.request('/api/generate', { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
    );
    return redactSecrets(cleanExplanation(data.response)); // a model can echo or invent credential-like text
  }
}

export interface ExplainResult {
  findings: Finding[];
  outcome: ExplainOutcome;
}

/** Explains the most severe findings first, one request at a time so a laptop GPU is not overloaded. */
export async function explainFindings(report: Report, client: OllamaClient, model: string, maxFindings: number): Promise<ExplainResult> {
  const notReady = await client.readiness();
  if (notReady) return { findings: report.findings, outcome: { status: 'skipped', model, explained: 0, reason: notReady } };

  const targets = new Set(
    [...report.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)).slice(0, maxFindings),
  );
  const explanations = new Map<Finding, string>();
  let failure: string | undefined;
  for (const finding of targets) {
    try {
      explanations.set(finding, await client.explain(finding));
    } catch (error) {
      failure = errorMessage(error);
      break;
    }
  }

  const findings = report.findings.map((f) => {
    const explanation = explanations.get(f);
    return explanation ? { ...f, explanation } : f;
  });
  const status = failure && explanations.size === 0 ? 'failed' : 'ok';
  return {
    findings,
    outcome: { status, model, explained: explanations.size, ...(failure ? { reason: redactSecrets(`stopped early: ${failure}`) } : {}) },
  };
}

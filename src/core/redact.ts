/**
 * Removes well-known credential formats from free text before it reaches a report, the terminal or a language model.
 * Gitleaks values never reach Guard at all; this protects the other paths: scanner messages, scanner error output and
 * AI explanations. Pattern matching cannot recognise every secret, so this reduces exposure rather than guaranteeing it.
 */
const PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];
// key = value or key: value, where the key names a secret (DB_PASSWORD, apiKey). The key stays readable; the value goes.
const ASSIGNMENT = /\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_]*)(\s*[:=]\s*)(["']?)([^\s"'`]{8,})\3/gi;

export const REDACTED = '[REDACTED]';

export function redactSecrets(text: string): string {
  let out = text;
  for (const pattern of PATTERNS) out = out.replace(pattern, REDACTED);
  return out.replace(ASSIGNMENT, (_m, key: string, sep: string, quote: string, value: string) =>
    value.startsWith('${{') || value === REDACTED ? `${key}${sep}${quote}${value}${quote}` : `${key}${sep}${quote}${REDACTED}${quote}`,
  );
}

export function redactOptional(text: string | undefined): string | undefined {
  return text === undefined ? undefined : redactSecrets(text);
}

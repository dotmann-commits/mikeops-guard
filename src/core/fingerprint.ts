import { createHash } from 'node:crypto';
import type { Finding, NewFinding } from './types.js';

const hash = (key: string): string => createHash('sha256').update(key).digest('hex').slice(0, 16);
const identity = (f: NewFinding): string => [f.scanner, f.ruleId, f.file ?? '', f.message].join('|');

/**
 * Version 2: scanner, rule, file and message, plus the occurrence number among identical findings in the same file.
 * The line is left out, so editing code above a finding keeps its fingerprint, and ignore rules keep matching.
 */
export function fingerprintAll(findings: readonly NewFinding[]): Finding[] {
  const order = findings.map((finding, index) => ({ finding, index }));
  order.sort((a, b) => (a.finding.line ?? 0) - (b.finding.line ?? 0) || a.index - b.index);
  const seen = new Map<string, number>();
  const prints = new Map<number, string>();
  for (const { finding, index } of order) {
    const key = identity(finding);
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    prints.set(index, hash(`v2|${key}|${occurrence}`));
  }
  return findings.map((finding, index) => ({ fingerprint: prints.get(index) ?? hash(`v2|${identity(finding)}|0`), ...finding }));
}

/** A single finding, as the first of its kind in its file. */
export function withFingerprint(finding: NewFinding): Finding {
  return fingerprintAll([finding])[0] as Finding;
}

/** Version 1 (0.1.0), which included the line. Still accepted by ignore rules so existing configs keep working. */
export function legacyFingerprint(finding: NewFinding): string {
  return hash([finding.scanner, finding.ruleId, finding.file ?? '', finding.line ?? '', finding.message].join('|'));
}

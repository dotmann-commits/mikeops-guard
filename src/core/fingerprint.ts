import { createHash } from 'node:crypto';
import type { Finding, NewFinding } from './types.js';

export function withFingerprint(finding: NewFinding): Finding {
  const key = [finding.scanner, finding.ruleId, finding.file ?? '', finding.line ?? '', finding.message].join('|');
  const fingerprint = createHash('sha256').update(key).digest('hex').slice(0, 16);
  return { fingerprint, ...finding };
}

import { describe, expect, it } from 'vitest';
import { configSchema } from '../../src/config/schema.js';
import { fingerprintAll, legacyFingerprint } from '../../src/core/fingerprint.js';
import { applyPolicy } from '../../src/core/policy.js';
import type { NewFinding } from '../../src/core/types.js';

const at = (line: number, message = 'Pin versions in apt-get install'): NewFinding => ({
  scanner: 'hadolint',
  ruleId: 'DL3008',
  title: 'Pin versions',
  severity: 'medium',
  category: 'container',
  file: 'Dockerfile',
  line,
  message,
  references: [],
});

describe('fingerprints', () => {
  it('stay the same when the finding moves to another line', () => {
    const [before] = fingerprintAll([at(10)]);
    const [after] = fingerprintAll([at(42)]);
    expect(before?.fingerprint).toBe(after?.fingerprint);
  });

  it('give identical findings in one file distinct fingerprints, stable regardless of input order', () => {
    const forward = fingerprintAll([at(5), at(9)]).map((f) => f.fingerprint);
    const reversed = fingerprintAll([at(9), at(5)]).map((f) => f.fingerprint);
    expect(new Set(forward).size).toBe(2);
    expect(reversed).toEqual([forward[1], forward[0]]); // the line-5 finding keeps its fingerprint
  });

  it('change when the message changes', () => {
    expect(fingerprintAll([at(1, 'a')])[0]?.fingerprint).not.toBe(fingerprintAll([at(1, 'b')])[0]?.fingerprint);
  });

  it('still honour ignore rules written with a 0.1.0 fingerprint', () => {
    const [finding] = fingerprintAll([at(12)]);
    if (!finding) throw new Error('no finding');
    const config = configSchema.parse({ ignore: [{ rule: legacyFingerprint(finding), reason: 'accepted' }] });
    expect(applyPolicy([finding], config)).toMatchObject({ kept: [], ignored: 1 });
    const byNew = configSchema.parse({ ignore: [{ rule: finding.fingerprint }] });
    expect(applyPolicy([finding], byNew).ignored).toBe(1);
  });
});

import { describe, expect, it } from 'vitest';
import { parseCliArgs } from '../../src/cli/args.js';
import { applyCliOverrides } from '../../src/cli/commands/overrides.js';
import { parseConfig } from '../../src/config/load.js';
import { UsageError } from '../../src/core/errors.js';

const parse = (argv: string[], env: NodeJS.ProcessEnv = {}) => parseCliArgs(argv, env, true);

describe('parseCliArgs', () => {
  it('defaults to help with no arguments', () => {
    expect(parse([])).toEqual({ command: 'help' });
  });

  it('parses scan options', () => {
    const parsed = parse(['scan', 'repo', '--fail-on', 'medium', '--only', 'gitleaks,hadolint', '--json', '-', '--explain']);
    expect(parsed).toMatchObject({
      command: 'scan',
      options: { path: 'repo', failOn: 'medium', only: ['gitleaks', 'hadolint'], json: '-', explain: true, color: true },
    });
  });

  it('turns color off for NO_COLOR', () => {
    const parsed = parse(['scan'], { NO_COLOR: '1' });
    expect(parsed.command === 'scan' && parsed.options.color).toBe(false);
  });

  it.each([
    [['scan', '--fail-on', 'urgent']],
    [['scan', '--only', 'semgrep']],
    [['scan', 'a', 'b']],
    [['deploy']],
    [['scan', '--bogus']],
    [['scan', '--max-findings', '-1']],
  ])('rejects %j with a UsageError', (argv) => {
    expect(() => parse(argv)).toThrow(UsageError);
  });
});

describe('applyCliOverrides', () => {
  it('lets flags win over the config without mutating it', () => {
    const config = parseConfig('failOn: low\nscanners:\n  hadolint:\n    enabled: false\n');
    const parsed = parse(['scan', '--only', 'hadolint,gitleaks', '--skip', 'gitleaks', '--fail-on', 'critical']);
    if (parsed.command !== 'scan') throw new Error('expected scan');
    const next = applyCliOverrides(config, parsed.options);
    expect(next.failOn).toBe('critical');
    expect(next.scanners.hadolint.enabled).toBe(true);
    expect(next.scanners.gitleaks.enabled).toBe(false);
    expect(next.scanners.actionlint.enabled).toBe(false);
    expect(config.scanners.hadolint.enabled).toBe(false);
  });
});

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
    const parsed = parse(['scan', 'repo', '--fail-on', 'medium', '--only', 'gitleaks,hadolint', '--json', 'report.json', '--sarif', 'report.sarif', '--markdown', '-', '--baseline', 'baseline.json', '--changed-since', 'origin/main', '--explain']);
    expect(parsed).toMatchObject({
      command: 'scan',
      options: { path: 'repo', failOn: 'medium', only: ['gitleaks', 'hadolint'], json: 'report.json', sarif: 'report.sarif', markdown: '-', baseline: 'baseline.json', changedSince: 'origin/main', explain: true, color: true },
    });
  });

  it('turns color off for NO_COLOR', () => {
    const parsed = parse(['scan'], { NO_COLOR: '1' });
    expect(parsed.command === 'scan' && parsed.options.color).toBe(false);
  });

  it('parses MCP mode with an optional confined root', () => {
    expect(parse(['mcp'])).toEqual({ command: 'mcp', root: '.' });
    expect(parse(['mcp', 'repo'])).toEqual({ command: 'mcp', root: 'repo' });
  });

  it('parses zero-token hook mode and optional agent protocol', () => {
    expect(parse(['hook'])).toEqual({ command: 'hook', options: { path: '.', agent: false, failOn: 'high' } });
    expect(parse(['hook', 'repo', '--agent', '--fail-on', 'critical'])).toEqual({ command: 'hook', options: { path: 'repo', agent: true, failOn: 'critical' } });
  });

  it('parses one-command guardrail installers', () => {
    expect(parse(['init', '--claude-hook', '--cursor-hook', '--pre-commit', '--skill'])).toEqual({
      command: 'init',
      options: { claudeHook: true, cursorHook: true, preCommit: true, skill: true },
    });
  });

  it.each([
    [['scan', '--fail-on', 'urgent']],
    [['scan', '--only', 'semgrep']],
    [['scan', 'a', 'b']],
    [['mcp', 'a', 'b']],
    [['hook', 'a', 'b']],
    [['deploy']],
    [['scan', '--bogus']],
    [['scan', '--max-findings', '-1']],
    [['scan', '--json', '-', '--sarif', '-']],
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

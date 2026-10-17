import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadConfig, parseConfig } from '../../src/config/load.js';
import { ConfigError } from '../../src/core/errors.js';

describe('parseConfig', () => {
  it('fills nested defaults for an empty file', () => {
    const config = parseConfig('');
    expect(config.failOn).toBe('high');
    expect(config.scanners.gitleaks).toEqual({ enabled: true, mode: 'auto' });
    expect(config.scanners.dependencies.engine).toBe('osv-scanner');
    expect(config.explain).toMatchObject({ enabled: false, host: 'http://127.0.0.1:11434' });
  });

  it('accepts partial sections and keeps other defaults', () => {
    const config = parseConfig('scanners:\n  hadolint:\n    enabled: false\n');
    expect(config.scanners.hadolint.enabled).toBe(false);
    expect(config.scanners.actionlint.enabled).toBe(true);
  });

  it('accepts JSON', () => {
    expect(parseConfig('{"failOn": "medium"}').failOn).toBe('medium');
  });

  it('rejects unknown keys and bad values with a readable path', () => {
    expect(() => parseConfig('failOn: urgent\nscannerz: {}\n', 'x.yml')).toThrow(ConfigError);
    try {
      parseConfig('failOn: urgent\n', 'x.yml');
    } catch (error) {
      expect((error as Error).message).toContain('failOn');
    }
  });

  it('rejects non-http explain hosts', () => {
    expect(() => parseConfig('explain:\n  host: file:///etc/passwd\n')).toThrow(ConfigError);
  });
});

describe('loadConfig', () => {
  it('reads the target root config and ignores the working directory', async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), 'guard-config-'));
    const root = path.join(base, 'repo');
    await mkdir(root);
    await writeFile(path.join(root, '.mikeops-guard.yml'), 'failOn: low\n');
    await writeFile(path.join(base, '.mikeops-guard.yml'), 'failOn: critical\n');
    const loaded = await loadConfig({ root, cwd: base });
    expect(loaded.config.failOn).toBe('low');
    expect(loaded.source).toBe(path.join(root, '.mikeops-guard.yml'));

    const other = path.join(base, 'other');
    await mkdir(other);
    expect((await loadConfig({ root: other, cwd: base })).source).toBeUndefined();
  });

  it('fails clearly when an explicit file is missing', async () => {
    await expect(loadConfig({ root: '/', cwd: '/', explicitPath: '/nope/guard.yml' })).rejects.toThrow('Config file not found');
  });
});

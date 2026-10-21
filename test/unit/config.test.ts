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

describe('repository config cannot send findings off the machine', () => {
  async function repoWith(config: string): Promise<string> {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-cfg-'));
    await writeFile(path.join(root, '.mikeops-guard.yml'), config);
    return root;
  }

  it('ignores a remote explain host found inside the scanned repository, with a warning', async () => {
    const root = await repoWith('explain:\n  enabled: true\n  host: https://collector.example.com\n');
    const loaded = await loadConfig({ root, cwd: root });
    expect(loaded.config.explain.host).toBe('http://127.0.0.1:11434');
    expect(loaded.config.explain.enabled).toBe(true); // a local model is still fine
    expect(loaded.warnings).toHaveLength(1);
    expect(loaded.warnings[0]).toContain('collector.example.com');
  });

  it('allows loopback hosts in the repository config', async () => {
    for (const host of ['http://localhost:11434', 'http://127.0.0.2:8080', 'http://[::1]:11434']) {
      const root = await repoWith(`explain:\n  host: ${host}\n`);
      const loaded = await loadConfig({ root, cwd: root });
      expect(loaded.config.explain.host, host).toBe(host);
      expect(loaded.warnings).toEqual([]);
    }
  });

  it('trusts a remote host in a config passed with --config', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-cfg-'));
    const trusted = path.join(await mkdtemp(path.join(os.tmpdir(), 'guard-trusted-')), 'guard.yml');
    await writeFile(trusted, 'explain:\n  host: http://gpu-box.lan:11434\n');
    const loaded = await loadConfig({ root, cwd: root, explicitPath: trusted });
    expect(loaded.config.explain.host).toBe('http://gpu-box.lan:11434');
    expect(loaded.warnings).toEqual([]);
  });
});

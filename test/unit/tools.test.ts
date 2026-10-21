import { chmod, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { installHint, resolveBinary } from '../../src/core/tools.js';

describe('resolveBinary', () => {
  it('finds executables on PATH and ignores non-executable files', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'guard-bin-'));
    await writeFile(path.join(dir, 'gitleaks'), '#!/bin/sh\n');
    await chmod(path.join(dir, 'gitleaks'), 0o755);
    await writeFile(path.join(dir, 'trivy'), 'not executable');
    expect(resolveBinary('gitleaks', dir, 'darwin')).toBe(path.join(dir, 'gitleaks'));
    expect(resolveBinary('trivy', dir, 'darwin')).toBeNull();
    expect(resolveBinary('gitleaks', '', 'darwin')).toBeNull();
  });

  it('never uses relative PATH entries, which could point into the scanned repository', async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), 'guard-path-'));
    const planted = path.join(repo, 'gitleaks');
    await writeFile(planted, '#!/bin/sh\necho pwned\n');
    await chmod(planted, 0o755);
    const previous = process.cwd();
    process.chdir(repo);
    try {
      expect(resolveBinary('gitleaks', ['.', 'bin', ''].join(path.delimiter), 'linux')).toBeNull();
      expect(resolveBinary('gitleaks', [repo].join(path.delimiter), 'linux')).toBe(planted); // absolute entries still work
    } finally {
      process.chdir(previous);
    }
  });

  it('gives install guidance', () => {
    expect(installHint('osv-scanner')).toContain('brew install osv-scanner');
  });
});

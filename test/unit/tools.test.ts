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

  it('gives install guidance', () => {
    expect(installHint('osv-scanner')).toContain('brew install osv-scanner');
  });
});

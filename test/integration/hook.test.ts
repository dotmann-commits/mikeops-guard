import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { CliIo } from '../../src/cli/io.js';
import { main } from '../../src/cli/main.js';

function capture(cwd: string): { io: CliIo; out: () => string; err: () => string } {
  let out = '';
  let err = '';
  return {
    io: { cwd, env: { PATH: '' }, isTty: false, stdout: (text) => void (out += text), stderr: (text) => void (err += text) },
    out: () => out,
    err: () => err,
  };
}

describe('mikeops-guard hook', () => {
  it('exits zero with exactly empty output when the trusted fast policy is clean', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-hook-clean-'));
    const run = capture(root);

    expect(await main(['hook'], run.io)).toBe(0);
    expect(run.out()).toBe('');
    expect(run.err()).toBe('');
  });

  it('returns a compact fix directive for a blocking finding', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-hook-finding-'));
    await mkdir(path.join(root, '.github/workflows'), { recursive: true });
    await writeFile(path.join(root, '.github/workflows/ci.yml'), [
      'on: issues', 'jobs:', '  unsafe:', '    runs-on: ubuntu-latest', '    steps:',
      '      - run: echo "${{ github.event.issue.title }}"',
    ].join('\n'));
    const run = capture(root);

    expect(await main(['hook'], run.io)).toBe(1);
    expect(run.err()).toBe('');
    expect(run.out().trim().split('\n')).toHaveLength(1);
    expect(run.out()).toMatch(/^HIGH \.github\/workflows\/ci\.yml:6 \[script-injection\] /);
    expect(run.out().length).toBeLessThan(500);
  });

  it('uses exit 2 and stderr so agent hooks feed findings back without normal stdout', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-hook-agent-'));
    await writeFile(path.join(root, '.cursorrules'), `safe${String.fromCodePoint(0xE0062)}hidden`);
    const run = capture(root);

    expect(await main(['hook', '--agent'], run.io)).toBe(2);
    expect(run.out()).toBe('');
    expect(run.err()).toContain('HIGH .cursorrules:1 [invisible-unicode-control]');
  });
});

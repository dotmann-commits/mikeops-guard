import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatBytes, readTextFile } from '../../src/core/files.js';

async function fileOfSize(bytes: number): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'guard-files-'));
  const file = path.join(dir, 'f.txt');
  await writeFile(file, 'a'.repeat(bytes));
  return file;
}

describe('readTextFile', () => {
  it('reads files up to and including the limit', async () => {
    expect(await readTextFile(await fileOfSize(10), 10)).toEqual({ ok: true, text: 'a'.repeat(10) });
    expect(await readTextFile(await fileOfSize(0), 10)).toEqual({ ok: true, text: '' });
  });

  it('refuses files over the limit without returning their content', async () => {
    const result = await readTextFile(await fileOfSize(3 * 1024 * 1024), 1024 * 1024);
    expect(result).toEqual({ ok: false, reason: 'larger than 1 MB' });
  });

  it('formats limits for people', () => {
    expect([formatBytes(512), formatBytes(512 * 1024), formatBytes(2 * 1024 * 1024)]).toEqual(['512 bytes', '512 KB', '2 MB']);
  });
});

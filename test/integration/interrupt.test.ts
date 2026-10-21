import { spawn } from 'node:child_process';
import { access, chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * Runs the built CLI as a real process and presses Ctrl+C (SIGINT) while a scanner is busy.
 * Needs `npm run build` first; CI builds before testing, and locally it is skipped without dist/.
 */
const CLI = path.resolve(import.meta.dirname, '../../dist/cli/index.js');
const FIXTURE = path.resolve(import.meta.dirname, '../fixtures/sample-repo');
const POSIX = process.platform !== 'win32';

const exists = (p: string) => access(p).then(() => true, () => false);

function isAlive(pid: number): boolean {
  if (pid <= 0) return false; // 0 would mean "my own process group"
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function until(check: () => Promise<boolean> | boolean, timeoutMs = 10_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return check();
}

describe.skipIf(!POSIX || !existsSync(CLI))('Ctrl+C on the real CLI', { timeout: 30_000 }, () => {
  let base: string;
  let repo: string;
  let bin: string;
  let state: string;

  beforeAll(async () => {
    base = await mkdtemp(path.join(os.tmpdir(), 'guard-interrupt-'));
    repo = path.join(base, 'repo');
    bin = path.join(base, 'bin');
    state = path.join(base, 'state');
    await cp(FIXTURE, repo, { recursive: true });
    // A fake gitleaks that starts a helper (like git) and records where Guard asked it to write its report.
    const fake = `#!/bin/sh\nsleep 60 &\necho $! > "${state}.helper"\necho "$@" > "${state}.args"\nwait\n`;
    await mkdir(bin, { recursive: true });
    await writeFile(path.join(bin, 'gitleaks'), fake);
    await chmod(path.join(bin, 'gitleaks'), 0o755);
  });

  afterAll(async () => {
    await rm(base, { recursive: true, force: true });
  });

  it('stops scanners and their helpers, removes temp files, writes no report and exits 130', async () => {
    const report = path.join(base, 'report.json');
    const child = spawn(process.execPath, [CLI, 'scan', repo, '--only', 'gitleaks', '--json', report], {
      env: { ...process.env, PATH: `${bin}:/usr/bin:/bin`, NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    const exited = new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code)));

    expect(await until(() => exists(`${state}.helper`))).toBe(true);
    const helper = Number((await readFile(`${state}.helper`, 'utf8')).trim());
    const args = (await readFile(`${state}.args`, 'utf8')).trim().split(' ');
    const tempDir = path.dirname(args[args.indexOf('--report-path') + 1] ?? '');
    expect(tempDir).toContain('mikeops-guard-');
    expect(await exists(tempDir)).toBe(true);

    child.kill('SIGINT');

    expect(await exited).toBe(130);
    expect(stderr).toContain('Scan cancelled');
    expect(await until(() => !isAlive(helper))).toBe(true);
    expect(await exists(tempDir)).toBe(false);
    expect(await exists(report)).toBe(false);
  });
});

import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { CancelledError, ExecTimeoutError } from '../../src/core/errors.js';
import { execCommand } from '../../src/core/exec.js';

const POSIX = process.platform !== 'win32';

/** pid 0 would mean "my own process group" to kill(), so it is never treated as a live helper. */
function isAlive(pid: number): boolean {
  if (pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function until(check: () => boolean | Promise<boolean>, timeoutMs = 3000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return check();
}

/** A shell that starts a long-running helper, like Gitleaks starting git, and records the helper's pid. */
async function scannerWithHelper(): Promise<{ args: string[]; helperPid: () => Promise<number> }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'guard-exec-'));
  const pidFile = path.join(dir, 'helper.pid');
  return {
    args: ['-c', `sleep 30 & echo $! > "${pidFile}"; wait`],
    helperPid: async () => {
      let pid = 0;
      await until(async () => {
        pid = Number((await readFile(pidFile, 'utf8').catch(() => '')).trim());
        return pid > 0;
      }, 10_000);
      return pid;
    },
  };
}

// Real processes on a busy CI runner or laptop can take seconds to start, so the default 5s budget is too tight.
describe.skipIf(!POSIX)('execCommand process lifecycle', { timeout: 20_000 }, () => {
  it('runs a command and returns its output and exit code', async () => {
    const result = await execCommand('sh', ['-c', 'echo out; echo err >&2; exit 3'], { cwd: os.tmpdir(), timeoutMs: 5000 });
    expect(result).toEqual({ code: 3, stdout: 'out\n', stderr: 'err\n' });
  });

  it('on timeout stops the scanner and every process it started', async () => {
    const { args, helperPid } = await scannerWithHelper();
    // Long enough for the shell to start its helper even on a loaded machine, so the test checks the kill, not a race.
    const run = execCommand('sh', args, { cwd: os.tmpdir(), timeoutMs: 6000 });
    const outcome = run.then(() => null, (error: unknown) => error);
    const pid = await helperPid();
    expect(pid).toBeGreaterThan(0);
    expect(isAlive(pid)).toBe(true);
    expect(await outcome).toBeInstanceOf(ExecTimeoutError);
    expect(await until(() => !isAlive(pid))).toBe(true);
  });

  it('on cancel stops the scanner and every process it started', async () => {
    const { args, helperPid } = await scannerWithHelper();
    const controller = new AbortController();
    const run = execCommand('sh', args, { cwd: os.tmpdir(), timeoutMs: 30_000, signal: controller.signal });
    const outcome = run.then(() => null, (error: unknown) => error);
    const pid = await helperPid();
    expect(pid).toBeGreaterThan(0);
    controller.abort();
    expect(await outcome).toBeInstanceOf(CancelledError);
    expect(await until(() => !isAlive(pid))).toBe(true);
  });

  it('does not start anything when the run was already cancelled', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(execCommand('sh', ['-c', 'exit 0'], { cwd: os.tmpdir(), timeoutMs: 1000, signal: controller.signal })).rejects.toBeInstanceOf(
      CancelledError,
    );
  });
});

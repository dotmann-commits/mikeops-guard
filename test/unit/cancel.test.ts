import { access, mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { installCancelHandlers, type SignalSource } from '../../src/cli/signals.js';
import { main } from '../../src/cli/main.js';
import { configSchema } from '../../src/config/schema.js';
import { CancelledError } from '../../src/core/errors.js';
import { runScan } from '../../src/core/run.js';
import type { Scanner } from '../../src/core/scanner.js';

/** A built-in scanner that waits until the run is cancelled, recording its temp dir. */
function waitingScanner(seen: { tempDir?: string }): Scanner {
  return {
    id: 'workflow-audit',
    title: 'Waits for cancel',
    category: 'workflow',
    tool: () => null,
    skipReason: () => null,
    run: (ctx) =>
      new Promise((_resolve, reject) => {
        seen.tempDir = ctx.tempDir;
        ctx.signal.addEventListener('abort', () => reject(new CancelledError()), { once: true });
      }),
  };
}

const exists = (p: string) => access(p).then(() => true, () => false);

describe('cancelling a scan', () => {
  it('rejects instead of returning a partial report, and removes the temp dir', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-cancel-'));
    const seen: { tempDir?: string } = {};
    const controller = new AbortController();
    const run = runScan({
      root,
      config: configSchema.parse({}),
      scanners: [waitingScanner(seen)],
      exec: () => Promise.reject(new Error('not used')),
      resolveBinary: () => null,
      toolVersion: '0.0.0',
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(seen.tempDir).toBeDefined());
    expect(await exists(seen.tempDir ?? '')).toBe(true);
    controller.abort();
    await expect(run).rejects.toBeInstanceOf(CancelledError);
    expect(await exists(seen.tempDir ?? '')).toBe(false);
  });

  it('makes the CLI exit 130 with a clear message and no report', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-cancel-cli-'));
    const seen: { tempDir?: string } = {};
    const controller = new AbortController();
    let out = '';
    let err = '';
    const io = { cwd: root, env: {}, isTty: false, stdout: (t: string) => void (out += t), stderr: (t: string) => void (err += t) };
    const run = main(['scan', root, '--json', path.join(root, 'report.json')], io, {
      scanners: [waitingScanner(seen)],
      resolveBinary: () => null,
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(seen.tempDir).toBeDefined());
    controller.abort();
    expect(await run).toBe(130);
    expect(err).toContain('Scan cancelled');
    expect(out).not.toContain('PASSED');
    expect(await exists(path.join(root, 'report.json'))).toBe(false);
  });
});

describe('signal handlers', () => {
  function fakeProcess() {
    const listeners = new Map<string, () => void>();
    const writes: string[] = [];
    const exit = vi.fn();
    const source: SignalSource = {
      on: (event, listener) => listeners.set(event, listener),
      once: (event, listener) => listeners.set(event, listener),
      exit: exit as unknown as SignalSource['exit'],
      stderr: { write: (text: string) => writes.push(text) },
    };
    return { source, exit, writes, send: (event: string) => listeners.get(event)?.() };
  }

  it('first signal cancels gracefully, second exits immediately with 130', () => {
    const fake = fakeProcess();
    const controller = new AbortController();
    installCancelHandlers(controller, fake.source);

    fake.send('SIGINT');
    expect(controller.signal.aborted).toBe(true);
    expect(fake.exit).not.toHaveBeenCalled();
    expect(fake.writes.join('')).toContain('Press Ctrl+C again');

    fake.send('SIGTERM');
    expect(fake.exit).toHaveBeenCalledWith(130);
  });
});

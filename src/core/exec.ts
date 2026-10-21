import { spawn, type ChildProcess } from 'node:child_process';
import { CancelledError, ExecTimeoutError, ScannerError, ToolMissingError } from './errors.js';

export interface ExecOptions {
  cwd: string;
  timeoutMs: number;
  /** Aborting stops the scanner and everything it started, then rejects with CancelledError. */
  signal?: AbortSignal;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type ExecFn = (command: string, args: readonly string[], options: ExecOptions) => Promise<ExecResult>;

const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;

/**
 * POSIX only: the scanner leads its own process group, so one kill reaches the helpers it starts (git under
 * Gitleaks, for example). Windows has no process groups; there only the scanner itself is stopped.
 */
const USE_PROCESS_GROUPS = process.platform !== 'win32';

export function killProcessTree(child: ChildProcess): void {
  if (child.pid === undefined || child.exitCode !== null) return;
  if (USE_PROCESS_GROUPS) {
    try {
      process.kill(-child.pid, 'SIGKILL');
      return;
    } catch {
      // The group is already gone; fall through to the single process.
    }
  }
  child.kill('SIGKILL');
}

/** Runs a binary without a shell, so arguments are never interpreted as shell syntax. */
export const execCommand: ExecFn = (command, args, options) =>
  new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(new CancelledError());
      return;
    }
    const child = spawn(command, args, {
      cwd: options.cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      // Its own group also means a terminal Ctrl+C reaches only Guard, which then stops the group cleanly.
      detached: USE_PROCESS_GROUPS,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let settled = false;

    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
      fn();
    };
    const stopWith = (error: Error): void => {
      killProcessTree(child);
      finish(() => reject(error));
    };
    const onAbort = (): void => stopWith(new CancelledError());

    const timer = setTimeout(() => stopWith(new ExecTimeoutError(command, options.timeoutMs)), options.timeoutMs);
    options.signal?.addEventListener('abort', onAbort, { once: true });

    const collect = (sink: Buffer[]) => (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        stopWith(new ScannerError(`${command} produced more than ${MAX_OUTPUT_BYTES} bytes of output`));
        return;
      }
      sink.push(chunk);
    };
    child.stdout?.on('data', collect(stdout));
    child.stderr?.on('data', collect(stderr));

    child.on('error', (error: NodeJS.ErrnoException) => {
      finish(() => reject(error.code === 'ENOENT' ? new ToolMissingError(command) : error));
    });
    child.on('close', (code, signal) => {
      finish(() =>
        resolve({
          code: code ?? (signal ? 128 : 1),
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
        }),
      );
    });
  });

/** Last few lines of stderr, for error messages that stay readable. */
export function stderrTail(stderr: string, lines = 5): string {
  return stderr.trim().split('\n').slice(-lines).join('\n');
}

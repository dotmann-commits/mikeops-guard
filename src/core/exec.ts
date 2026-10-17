import { spawn } from 'node:child_process';
import { ExecTimeoutError, ScannerError, ToolMissingError } from './errors.js';

export interface ExecOptions {
  cwd: string;
  timeoutMs: number;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type ExecFn = (command: string, args: readonly string[], options: ExecOptions) => Promise<ExecResult>;

const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;

/** Runs a binary without a shell, so arguments are never interpreted as shell syntax. */
export const execCommand: ExecFn = (command, args, options) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let settled = false;

    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(() => reject(new ExecTimeoutError(command, options.timeoutMs)));
    }, options.timeoutMs);

    const collect = (sink: Buffer[]) => (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        child.kill('SIGKILL');
        finish(() => reject(new ScannerError(`${command} produced more than ${MAX_OUTPUT_BYTES} bytes of output`)));
        return;
      }
      sink.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));

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

import { EXIT_CODES } from '../core/exit-codes.js';

/** The parts of `process` the handlers need, so tests can drive them with a fake. */
export interface SignalSource {
  once(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
  on(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
  exit(code: number): never;
  stderr: { write(text: string): unknown };
}

/**
 * First Ctrl+C or SIGTERM aborts the scan gracefully: scanners are stopped, temp files removed, and main exits 130.
 * A second one exits at once, for when clean-up itself is stuck.
 */
export function installCancelHandlers(controller: AbortController, source: SignalSource): void {
  let cancelling = false;
  const handle = (): void => {
    if (cancelling) {
      source.exit(EXIT_CODES.cancelled);
      return;
    }
    cancelling = true;
    source.stderr.write('\nStopping scanners. Press Ctrl+C again to exit immediately.\n');
    controller.abort();
  };
  source.on('SIGINT', handle);
  source.on('SIGTERM', handle);
}

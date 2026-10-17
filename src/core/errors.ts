/** Base class for errors that carry a friendly message meant for the terminal. */
export class GuardError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class UsageError extends GuardError {}

export class ConfigError extends GuardError {}

export class ToolMissingError extends GuardError {
  constructor(readonly binary: string) {
    super(`${binary} is not installed or not on PATH`);
  }
}

export class ExecTimeoutError extends GuardError {
  constructor(binary: string, timeoutMs: number) {
    super(`${binary} did not finish within ${Math.round(timeoutMs / 1000)}s`);
  }
}

export class ScannerError extends GuardError {}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

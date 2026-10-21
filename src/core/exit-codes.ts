export const EXIT_CODES = {
  pass: 0,
  policyFailed: 1,
  usage: 2,
  scannerFailed: 3,
  /** 128 + SIGINT, the shell convention for a run stopped by Ctrl+C. */
  cancelled: 130,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

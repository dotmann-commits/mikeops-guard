export const EXIT_CODES = {
  pass: 0,
  policyFailed: 1,
  usage: 2,
  scannerFailed: 3,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

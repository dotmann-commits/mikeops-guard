export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SCANNER_IDS = [
  'hadolint',
  'trivy-config',
  'actionlint',
  'workflow-audit',
  'gitleaks',
  'dependencies',
  'app-security',
] as const;
export type ScannerId = (typeof SCANNER_IDS)[number];

export type Category = 'container' | 'iac' | 'workflow' | 'secret' | 'dependency' | 'application';

export interface Finding {
  /** Stable hash of scanner, rule, file, message and occurrence (not the line). Useful for ignores and baselines. */
  fingerprint: string;
  scanner: ScannerId;
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  /** Path relative to the scanned root, always with forward slashes. */
  file?: string;
  line?: number;
  message: string;
  remediation?: string;
  references: string[];
  explanation?: string;
}

export type NewFinding = Omit<Finding, 'fingerprint'>;

export type ScannerStatus = 'ok' | 'skipped' | 'failed';

export interface ScannerOutcome {
  scanner: ScannerId;
  title: string;
  status: ScannerStatus;
  durationMs: number;
  findingCount: number;
  /**
   * True when this scanner should have checked the target but did not: not installed, failed, timed out, or disabled
   * by the config or --only/--skip. False for "nothing to check" skips such as a repository without Dockerfiles.
   */
  incomplete: boolean;
  reason?: string;
  installHint?: string;
  /** Files this scanner did not check, for example because they were too large. Capped, see skippedFileCount. */
  skippedFiles?: { file: string; reason: string }[];
  skippedFileCount?: number;
}

/** passed: no findings at the threshold and every scanner ran. incomplete: no findings at the threshold, but coverage gaps. */
export type ReportStatus = 'passed' | 'failed' | 'incomplete';

export type SeverityCounts = Record<Severity, number>;

export interface ExplainOutcome {
  status: ScannerStatus;
  model: string;
  explained: number;
  reason?: string;
}

export interface Report {
  schemaVersion: 1;
  tool: { name: string; version: string };
  target: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  failOn: Severity | 'none';
  /** Policy result only: true when no kept finding is at or above failOn. Read `status` for coverage as well. */
  passed: boolean;
  status: ReportStatus;
  summary: SeverityCounts & { total: number; ignored: number };
  scanners: ScannerOutcome[];
  findings: Finding[];
  explain?: ExplainOutcome;
}

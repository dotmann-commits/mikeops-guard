export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SCANNER_IDS = [
  'hadolint',
  'trivy-config',
  'actionlint',
  'workflow-audit',
  'gitleaks',
  'dependencies',
] as const;
export type ScannerId = (typeof SCANNER_IDS)[number];

export type Category = 'container' | 'iac' | 'workflow' | 'secret' | 'dependency';

export interface Finding {
  /** Stable hash of scanner, rule, location and message. Useful for dedupe and baselines. */
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
  reason?: string;
  installHint?: string;
}

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
  passed: boolean;
  summary: SeverityCounts & { total: number; ignored: number };
  scanners: ScannerOutcome[];
  findings: Finding[];
  explain?: ExplainOutcome;
}

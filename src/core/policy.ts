import type { GuardConfig, IgnoreRule } from '../config/schema.js';
import { EXIT_CODES, type ExitCode } from './exit-codes.js';
import { legacyFingerprint } from './fingerprint.js';
import { createMatcher, globToRegExp } from './glob.js';
import { SEVERITIES, type Finding, type Report, type Severity, type SeverityCounts } from './types.js';

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

export function meetsThreshold(severity: Severity, failOn: Severity | 'none'): boolean {
  if (failOn === 'none') return false;
  return RANK[severity] >= RANK[failOn];
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    RANK[b.severity] - RANK[a.severity] ||
    (a.file ?? '').localeCompare(b.file ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

function ruleMatches(rule: IgnoreRule, finding: Finding): boolean {
  const ruleId = rule.rule;
  const idMatches =
    ruleId === finding.ruleId ||
    ruleId === `${finding.scanner}:${finding.ruleId}` ||
    ruleId === finding.fingerprint ||
    ruleId === legacyFingerprint(finding);
  if (!idMatches) return false;
  if (!rule.path) return true;
  return finding.file !== undefined && globToRegExp(rule.path).test(finding.file);
}

export interface PolicyResult {
  kept: Finding[];
  ignored: number;
}

/** Applies severity overrides, excludes and ignore rules from the config. */
export function applyPolicy(findings: readonly Finding[], config: GuardConfig): PolicyResult {
  const excluded = createMatcher(config.exclude);
  const kept: Finding[] = [];
  let ignored = 0;

  for (const finding of findings) {
    const override = config.severityOverrides[finding.ruleId];
    const adjusted = override ? { ...finding, severity: override } : finding;
    const isExcluded = adjusted.file !== undefined && excluded(adjusted.file);
    if (isExcluded || config.ignore.some((rule) => ruleMatches(rule, adjusted))) {
      ignored++;
      continue;
    }
    kept.push(adjusted);
  }
  return { kept: kept.sort(compareFindings), ignored };
}

export function countBySeverity(findings: readonly Finding[]): SeverityCounts {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
  for (const finding of findings) counts[finding.severity]++;
  return counts;
}

/** A policy failure outranks a scanner failure, because it is the more actionable signal. */
export function exitCodeFor(report: Report): ExitCode {
  if (!report.passed) return EXIT_CODES.policyFailed;
  if (report.scanners.some((s) => s.status === 'failed')) return EXIT_CODES.scannerFailed;
  return EXIT_CODES.pass;
}

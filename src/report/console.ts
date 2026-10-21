import { SEVERITIES, type Finding, type Report, type Severity } from '../core/types.js';
import { terminalSafe as t } from './terminal.js';

export interface ConsoleOptions {
  color: boolean;
  /** Maximum findings to print in detail. The full list is always in JSON and HTML. */
  maxFindings: number;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '\x1b[1;31m',
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[36m',
  info: '\x1b[90m',
};
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

export function renderConsole(report: Report, options: ConsoleOptions): string {
  const paint = (code: string, text: string): string => (options.color ? `${code}${text}${RESET}` : text);
  const lines: string[] = [];

  lines.push(paint(BOLD, 'MikeOps Guard'), paint(DIM, `Target: ${t(report.target)}`), '');
  lines.push('Scanners');
  for (const s of report.scanners) {
    const status = s.status === 'ok' ? paint('\x1b[32m', 'ok     ') : s.status === 'skipped' ? paint(DIM, 'skipped') : paint('\x1b[31m', 'failed ');
    const detail = s.status === 'ok' ? `${s.findingCount} finding(s)${s.reason ? `; ${t(s.reason)}` : ''}` : t(s.reason ?? '');
    lines.push(`  ${status}  ${t(s.title).padEnd(44)} ${paint(DIM, detail)}`);
    if (s.installHint) lines.push(`           ${paint(DIM, t(s.installHint))}`);
  }
  lines.push('');

  const shown = report.findings.slice(0, options.maxFindings);
  if (shown.length > 0) {
    lines.push('Findings');
    for (const finding of shown) lines.push(...renderFinding(finding, paint));
    if (report.findings.length > shown.length) {
      lines.push(paint(DIM, `  ... and ${report.findings.length - shown.length} more. Use --json or --html for the full list.`), '');
    }
  }

  const counts = SEVERITIES.filter((s) => report.summary[s] > 0)
    .map((s) => paint(SEVERITY_COLORS[s], `${report.summary[s]} ${s}`))
    .join(', ');
  lines.push(`Summary: ${report.summary.total} finding(s)${counts ? ` (${counts})` : ''}, ${report.summary.ignored} ignored`);
  lines.push(`Result:  ${verdictLine(report, paint)}`);
  return `${lines.join('\n')}\n`;
}

function renderFinding(finding: Finding, paint: (code: string, text: string) => string): string[] {
  const where = finding.file ? `${t(finding.file)}${finding.line ? `:${finding.line}` : ''}` : 'repository';
  const lines = [
    `  ${paint(SEVERITY_COLORS[finding.severity], finding.severity.toUpperCase().padEnd(8))} ${t(finding.title)}`,
    `           ${paint(DIM, `${where}  [${finding.scanner}/${t(finding.ruleId)}]`)}`,
    `           ${t(finding.message)}`,
  ];
  if (finding.remediation) lines.push(`           Fix: ${t(finding.remediation)}`);
  if (finding.explanation) lines.push(...t(finding.explanation).split('\n').map((l) => `           ${paint(DIM, l)}`));
  lines.push('');
  return lines;
}

function verdictLine(report: Report, paint: (code: string, text: string) => string): string {
  if (report.status === 'failed') return paint('\x1b[1;31m', `FAILED: findings at or above "${report.failOn}"`);
  if (report.status === 'passed') return paint('\x1b[1;32m', 'PASSED');
  const missing = report.scanners.filter((s) => s.incomplete).map((s) => s.scanner);
  // Never a clean pass: say what was not checked.
  return paint('\x1b[1;33m', `INCOMPLETE: nothing at or above "${report.failOn}", but ${missing.length} scanner(s) did not run: ${missing.join(', ')}`);
}

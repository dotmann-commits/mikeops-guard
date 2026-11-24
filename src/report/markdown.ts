import type { Report } from '../core/types.js';
import { correlateAttackPaths } from './attack-paths.js';

const MAX_MARKDOWN_FINDINGS = 100;

function escapeMarkdown(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('|', '\\|')
    .replace(/[\r\n]+/g, ' ');
}

function inlineCode(value: string): string {
  const escaped = escapeMarkdown(value);
  return value.includes('`') ? `<code>${escaped.replaceAll('`', '&#96;')}</code>` : `\`${escaped}\``;
}

function verdict(report: Report): string {
  return report.status === 'failed' ? 'Failed' : report.status === 'passed' ? 'Passed' : 'Incomplete';
}

export function renderMarkdown(report: Report): string {
  const lines = [
    `# MikeOps Guard — ${verdict(report)}`,
    '',
    `Target: ${inlineCode(report.target)} · ${(report.durationMs / 1000).toFixed(1)}s · fail on ${inlineCode(report.failOn)}`,
    '',
    '| Critical | High | Medium | Low | Info | Ignored |',
    '|---:|---:|---:|---:|---:|---:|',
    `| ${report.summary.critical} | ${report.summary.high} | ${report.summary.medium} | ${report.summary.low} | ${report.summary.info} | ${report.summary.ignored} |`,
    '',
  ];
  const gaps = report.scanners.filter((scanner) => scanner.incomplete);
  if (gaps.length > 0) {
    lines.push(`> **Incomplete coverage:** ${gaps.map((scanner) => escapeMarkdown(scanner.title)).join(', ')} did not complete.`, '');
  }
  if (report.scope) {
    const scope = [
      report.scope.baseline ? `${report.scope.baselineSuppressed} baseline finding(s)` : '',
      report.scope.changedSince ? `${report.scope.unchangedSuppressed} unchanged finding(s) outside ${report.scope.changedFiles ?? 0} changed file(s) since ${inlineCode(report.scope.changedSince)}` : '',
    ].filter(Boolean).join(' and ');
    lines.push(`> **Adoption scope:** Suppressed ${scope}.`, '');
  }
  const attackPaths = correlateAttackPaths(report.findings);
  if (attackPaths.length > 0) {
    lines.push('## Potential attack paths', '', '> Correlations are plausible chains, not proof of exploitation.', '');
    for (const path of attackPaths) {
      lines.push(`- **${escapeMarkdown(path.severity.toUpperCase())}: ${escapeMarkdown(path.title)}** — ${path.stages.map((stage) => escapeMarkdown(stage.label)).join(' → ')}`);
    }
    lines.push('');
  }
  if (report.findings.length === 0) {
    lines.push('No findings.', '');
    return `${lines.join('\n')}\n`;
  }
  lines.push('## Findings', '', '| Severity | Rule | Location | Finding | Fix |', '|---|---|---|---|---|');
  for (const finding of report.findings.slice(0, MAX_MARKDOWN_FINDINGS)) {
    const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : 'repository';
    lines.push(`| **${finding.severity.toUpperCase()}** | ${inlineCode(`${finding.scanner}/${finding.ruleId}`)} | ${inlineCode(location)} | ${escapeMarkdown(finding.title)} | ${escapeMarkdown(finding.remediation ?? '—')} |`);
  }
  if (report.findings.length > MAX_MARKDOWN_FINDINGS) {
    lines.push('', `_${report.findings.length - MAX_MARKDOWN_FINDINGS} additional findings omitted from this summary; use JSON, SARIF or HTML for the complete report._`);
  }
  return `${lines.join('\n')}\n`;
}

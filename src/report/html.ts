import { createHash } from 'node:crypto';
import { SEVERITIES, type Finding, type Report, type ScannerOutcome } from '../core/types.js';
import { escapeHtml, safeUrl } from './escape.js';
import { HTML_STYLES } from './html-styles.js';
import { correlateAttackPaths } from './attack-paths.js';
import { securityGrade } from './security-grade.js';

// Tiny inline filter script. The report must work offline, so nothing is loaded from a CDN.
const FILTER_SCRIPT = `
document.querySelectorAll('[data-filter]').forEach(function (box) {
  box.addEventListener('change', function () {
    document.querySelectorAll('.finding[data-severity="' + box.value + '"]').forEach(function (el) {
      el.hidden = !box.checked;
    });
  });
});`;
// Only this exact script may run: anything injected despite escaping would not match the hash.
const SCRIPT_HASH = `sha256-${createHash('sha256').update(FILTER_SCRIPT).digest('base64')}`;

function renderCards(report: Report): string {
  const cards = SEVERITIES.map(
    (s) => `<div class="card"><div class="n sev-${s}">${report.summary[s]}</div><div class="l">${s}</div></div>`,
  );
  cards.push(`<div class="card"><div class="n">${report.summary.ignored}</div><div class="l">ignored</div></div>`);
  return `<section class="cards">${cards.join('')}</section>`;
}

function renderScannerRow(outcome: ScannerOutcome): string {
  const note = [outcome.reason, outcome.installHint].filter(Boolean).map((n) => escapeHtml(n ?? '')).join('<br>');
  return `<tr>
    <td>${escapeHtml(outcome.title)}</td>
    <td class="status status-${outcome.status}">${outcome.status}${outcome.incomplete ? ' (not checked)' : ''}</td>
    <td>${(outcome.durationMs / 1000).toFixed(1)}s</td>
    <td>${outcome.findingCount}</td>
    <td>${note}</td>
  </tr>`;
}

function renderReferences(references: readonly string[]): string {
  if (references.length === 0) return '';
  const links = references.map((ref) => {
    const url = safeUrl(ref);
    return url
      ? `<a href="${escapeHtml(url)}" rel="noopener noreferrer" target="_blank">${escapeHtml(ref)}</a>`
      : escapeHtml(ref);
  });
  return `<p class="refs">References: ${links.join(' · ')}</p>`;
}

function renderFinding(finding: Finding): string {
  const where = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : 'repository';
  return `<article class="finding" data-severity="${finding.severity}">
    <h3><span class="badge sev-${finding.severity}">${finding.severity}</span>${escapeHtml(finding.title)}</h3>
    <div class="where">${escapeHtml(where)} · ${escapeHtml(finding.scanner)} · ${escapeHtml(finding.ruleId)}</div>
    <p>${escapeHtml(finding.message)}</p>
    ${finding.remediation ? `<p class="fix"><strong>Fix:</strong> ${escapeHtml(finding.remediation)}</p>` : ''}
    ${finding.explanation ? `<p class="ai"><strong>Local AI explanation:</strong>\n${escapeHtml(finding.explanation)}</p>` : ''}
    ${renderReferences(finding.references)}
  </article>`;
}

function renderFilters(report: Report): string {
  return `<div class="filters">${SEVERITIES.filter((s) => report.summary[s] > 0)
    .map((s) => `<label><input type="checkbox" data-filter value="${s}" checked> ${s} (${report.summary[s]})</label>`)
    .join('')}</div>`;
}

function compactLabel(value: string, max = 24): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

function renderAttackGraph(path: ReturnType<typeof correlateAttackPaths>[number], index: number): string {
  const positions = path.stages.length === 2 ? [190, 770] : [100, 480, 860];
  const marker = `attack-arrow-${index}`;
  const lines = path.stages.slice(0, -1).map((_, stageIndex) =>
    `<line x1="${positions[stageIndex]! + 76}" y1="70" x2="${positions[stageIndex + 1]! - 76}" y2="70" marker-end="url(#${marker})"/>`,
  ).join('');
  const nodes = path.stages.map((stage, stageIndex) => {
    const x = positions[stageIndex]!;
    const where = stage.file ? compactLabel(stage.file) : 'repository';
    return `<g class="attack-node" transform="translate(${x} 70)">
      <circle r="54"/><text class="node-index" y="-10">0${stageIndex + 1}</text>
      <text class="node-label" y="14">${escapeHtml(compactLabel(stage.label, 20))}</text>
      <text class="node-file" y="84">${escapeHtml(where)}</text>
    </g>`;
  }).join('');
  return `<svg class="attack-graph" viewBox="0 0 960 180" role="img" aria-label="Attack path: ${escapeHtml(path.title)}">
    <defs><marker id="${marker}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"/></marker></defs>
    <g class="attack-connectors">${lines}</g>${nodes}
  </svg>`;
}

function renderAttackPaths(report: Report): string {
  const paths = correlateAttackPaths(report.findings);
  if (paths.length === 0) return '';
  return `<h2>Potential attack paths</h2>
  <p class="meta">Correlations identify plausible blast-radius chains from coexisting findings; they do not prove exploitability.</p>
  <section class="attack-paths">${paths.map((path, index) => `<article class="attack-path">
    <h3><span class="badge sev-${path.severity}">${path.severity}</span>${escapeHtml(path.title)}</h3>
    <p>${escapeHtml(path.summary)}</p>
    ${renderAttackGraph(path, index)}
    <ol>${path.stages.map((stage) => {
      const where = stage.file ? `${stage.file}${stage.line ? `:${stage.line}` : ''}` : 'repository';
      return `<li><strong>${escapeHtml(stage.label)}</strong><span>${escapeHtml(where)} · ${escapeHtml(stage.scanner)}/${escapeHtml(stage.ruleId)}</span></li>`;
    }).join('')}</ol>
  </article>`).join('')}</section>`;
}

function renderGrade(report: Report): string {
  const grade = securityGrade(report);
  return `<section class="grade-panel" aria-label="Security Grade ${grade.letter}, ${grade.score} out of 100">
    <div class="grade-ring" style="--grade-score: ${grade.score}%"><span class="grade-letter">${grade.letter}</span><span class="grade-score">${grade.score}/100</span></div>
    <div><div class="eyebrow">Security Grade</div><h2>${grade.complete ? 'Measured risk signal' : 'Coverage-limited signal'}</h2>
    <p>${escapeHtml(grade.rationale)} This grade summarizes detected evidence; it is not a security certification.</p></div>
  </section>`;
}

function renderScope(report: Report): string {
  if (!report.scope) return '';
  const parts = [
    report.scope.baseline ? `baseline ${report.scope.baseline}: ${report.scope.baselineSuppressed} existing finding(s) suppressed` : '',
    report.scope.changedSince ? `changed since ${report.scope.changedSince}: ${report.scope.changedFiles ?? 0} file(s), ${report.scope.unchangedSuppressed} unchanged finding(s) suppressed` : '',
  ].filter(Boolean);
  return `<p class="scope"><strong>Adoption scope:</strong> ${escapeHtml(parts.join(' · '))}</p>`;
}

export function renderHtml(report: Report): string {
  const verdict =
    report.status === 'failed'
      ? '<span class="verdict fail">Failed</span>'
      : report.status === 'passed'
        ? '<span class="verdict pass">Passed</span>'
        : '<span class="verdict warn">Incomplete</span>';
  const gaps = report.scanners.filter((s) => s.incomplete);
  const coverage =
    gaps.length === 0
      ? ''
      : `<p class="coverage"><strong>Incomplete scan:</strong> ${gaps.length} scanner(s) did not run, so this report is not a clean result: ${gaps.map((s) => escapeHtml(s.title)).join(', ')}.</p>`;
  const findings =
    report.findings.length === 0
      ? '<div class="empty">No findings. Nice work.</div>'
      : `${renderFilters(report)}${report.findings.map(renderFinding).join('\n')}`;
  const explain = report.explain
    ? `<p class="meta">Local AI explanations: ${escapeHtml(report.explain.status)} (${escapeHtml(report.explain.model)}, ${report.explain.explained} explained)${report.explain.reason ? `. ${escapeHtml(report.explain.reason)}` : ''}</p>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src '${SCRIPT_HASH}'; base-uri 'none'; form-action 'none'">
<title>MikeOps Guard Report</title>
<style>${HTML_STYLES}</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>MikeOps Guard Report</h1>
      <div class="meta">Target <code>${escapeHtml(report.target)}</code><br>
      ${escapeHtml(report.finishedAt)} · ${(report.durationMs / 1000).toFixed(1)}s · fail on ${escapeHtml(report.failOn)} · v${escapeHtml(report.tool.version)}</div>
    </div>
    ${verdict}
  </header>
  ${coverage}
  ${renderScope(report)}
  ${renderGrade(report)}
  ${renderCards(report)}
  ${renderAttackPaths(report)}
  <h2>Scanners</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Scanner</th><th>Status</th><th>Time</th><th>Findings</th><th>Notes</th></tr></thead>
    <tbody>${report.scanners.map(renderScannerRow).join('')}</tbody>
  </table></div>
  ${explain}
  <h2>Findings (${report.summary.total})</h2>
  ${findings}
</main>
<script>${FILTER_SCRIPT}</script>
</body>
</html>
`;
}

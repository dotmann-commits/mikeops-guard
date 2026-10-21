import { createHash } from 'node:crypto';
import { SEVERITIES, type Finding, type Report, type ScannerOutcome } from '../core/types.js';
import { escapeHtml, safeUrl } from './escape.js';
import { HTML_STYLES } from './html-styles.js';

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
  ${renderCards(report)}
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

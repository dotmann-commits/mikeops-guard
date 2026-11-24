import type { Finding, Report, Severity } from '../core/types.js';

const SARIF_SCHEMA = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note',
};
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5', high: '8.0', medium: '5.5', low: '2.0', info: '0.1',
};

function sarifRuleId(finding: Finding): string {
  return `${finding.scanner}/${finding.ruleId}`;
}

function artifactUri(file: string): string {
  return file.split('/').map(encodeURIComponent).join('/');
}

export function renderSarif(report: Report): string {
  const rules = new Map<string, Finding>();
  for (const finding of report.findings) rules.set(sarifRuleId(finding), rules.get(sarifRuleId(finding)) ?? finding);
  const results = report.findings.map((finding) => ({
    ruleId: sarifRuleId(finding),
    level: LEVEL[finding.severity],
    message: { text: finding.message },
    ...(finding.file ? {
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: artifactUri(finding.file) },
          ...(finding.line ? { region: { startLine: finding.line } } : {}),
        },
      }],
    } : {}),
    partialFingerprints: { 'mikeopsGuardFingerprint/v1': finding.fingerprint },
    properties: { scanner: finding.scanner, severity: finding.severity, category: finding.category },
  }));
  const log = {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'MikeOps Guard',
          semanticVersion: report.tool.version,
          version: report.tool.version,
          informationUri: 'https://github.com/dotmann-commits/mikeops-guard',
          rules: [...rules].map(([id, finding]) => ({
            id,
            name: finding.ruleId,
            shortDescription: { text: finding.title },
            fullDescription: { text: finding.message },
            help: { text: finding.remediation ?? finding.message },
            defaultConfiguration: { level: LEVEL[finding.severity] },
            properties: {
              tags: ['security', finding.category, finding.scanner],
              precision: 'high',
              'security-severity': SECURITY_SEVERITY[finding.severity],
            },
          })),
        },
      },
      invocations: [{
        executionSuccessful: report.status !== 'incomplete',
        startTimeUtc: report.startedAt,
        endTimeUtc: report.finishedAt,
        properties: { status: report.status, failOn: report.failOn },
      }],
      results,
    }],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}

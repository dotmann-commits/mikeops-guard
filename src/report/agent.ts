import { meetsThreshold } from '../core/policy.js';
import type { Severity } from '../core/types.js';
import type { McpFinding } from '../mcp/scan.js';
import { terminalSafe } from './terminal.js';

const MAX_DIRECTIVES = 20;
const MAX_DIRECTIVE_CHARS = 240;

function compact(value: string): string {
  const clean = terminalSafe(value).replace(/\s+/g, ' ').trim();
  return clean.length <= MAX_DIRECTIVE_CHARS ? clean : `${clean.slice(0, MAX_DIRECTIVE_CHARS - 1)}…`;
}

export function renderAgentDirectives(findings: readonly McpFinding[], failOn: Severity | 'none'): string {
  const directives = findings
    .filter((finding) => meetsThreshold(finding.severity, failOn))
    .slice(0, MAX_DIRECTIVES)
    .map((finding) => {
      const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : 'repository';
      return `${finding.severity.toUpperCase()} ${compact(location)} [${compact(finding.ruleId)}] ${compact(finding.remediation ?? finding.message)}`;
    });
  return directives.length > 0 ? `${directives.join('\n')}\n` : '';
}

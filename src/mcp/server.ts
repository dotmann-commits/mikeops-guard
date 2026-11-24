import { realpath, stat } from 'node:fs/promises';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { toolVersion } from '../cli/version.js';
import { errorMessage } from '../core/errors.js';
import { redactSecrets } from '../core/redact.js';
import { SEVERITIES } from '../core/types.js';
import { scanRepositoryForMcp, type McpScanOutput } from './scan.js';

export interface McpServerHandle {
  close(): Promise<void>;
}

const failOnSchema = z.enum([...SEVERITIES, 'none']);
const scanInputSchema = z.strictObject({
  path: z.string().min(1).max(500).default('.').describe('Directory relative to the MCP server root to scan.'),
  mode: z.enum(['fast', 'full']).default('fast').describe('fast runs built-in scanners; full also runs configured external scanners.'),
  fail_on: failOnSchema.default('high').describe('Lowest finding severity that marks the scan failed.'),
  max_findings: z.number().int().min(1).max(100).default(50).describe('Maximum detailed findings returned to the agent.'),
});

const findingSchema = z.strictObject({
  fingerprint: z.string(),
  scanner: z.string(),
  ruleId: z.string(),
  severity: z.enum(SEVERITIES),
  title: z.string(),
  message: z.string(),
  file: z.string().optional(),
  line: z.number().int().positive().optional(),
  remediation: z.string().optional(),
});

const scanOutputSchema = z.strictObject({
  status: z.enum(['passed', 'failed', 'incomplete']),
  passed: z.boolean(),
  target: z.string(),
  mode: z.enum(['fast', 'full']),
  durationMs: z.number().nonnegative(),
  totalFindings: z.number().int().nonnegative(),
  truncated: z.boolean(),
  summary: z.record(z.string(), z.number()),
  coverageGaps: z.array(z.strictObject({ scanner: z.string(), reason: z.string() })),
  findings: z.array(findingSchema),
});

function resultText(output: McpScanOutput): string {
  const lines = [
    `MikeOps Guard: ${output.status.toUpperCase()} — ${output.totalFindings} finding(s) in ${output.durationMs} ms.`,
  ];
  for (const finding of output.findings) {
    const location = finding.file ? ` ${finding.file}${finding.line ? `:${finding.line}` : ''}` : '';
    lines.push(`${finding.severity.toUpperCase()} ${finding.ruleId}${location}: ${finding.title}`);
  }
  if (output.truncated) lines.push('Additional findings were omitted; increase max_findings up to 100 to inspect more.');
  if (output.coverageGaps.length > 0) lines.push(`Coverage gaps: ${output.coverageGaps.map((gap) => gap.scanner).join(', ')}.`);
  return lines.join('\n');
}

export function createMcpServer(root: string): McpServer {
  const server = new McpServer(
    { name: 'mikeops-guard-mcp-server', version: toolVersion() },
    { instructions: 'Use mikeops_scan_repository before committing generated workflows, migrations, application code or MCP configuration. Fast mode is read-only and runs built-in checks without network access.' },
  );
  server.registerTool(
    'mikeops_scan_repository',
    {
      title: 'Scan repository with MikeOps Guard',
      description: 'Read-only security scan of a directory beneath the configured repository root. Fast mode always runs workflow-audit, app-security and ai-supply-chain. Full mode follows repository configuration and may invoke installed external scanners.',
      inputSchema: scanInputSchema,
      outputSchema: scanOutputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ path, mode, fail_on, max_findings }) => {
      try {
        const output = await scanRepositoryForMcp(root, { path, mode, failOn: fail_on, maxFindings: max_findings });
        return { content: [{ type: 'text', text: resultText(output) }], structuredContent: output };
      } catch (error) {
        const message = redactSecrets(errorMessage(error));
        return {
          isError: true,
          content: [{ type: 'text', text: `MikeOps Guard could not scan this path: ${message}` }],
        };
      }
    },
  );
  return server;
}

export async function startMcpStdio(root: string, log: (text: string) => void): Promise<McpServerHandle> {
  const resolved = await realpath(root);
  if (!(await stat(resolved)).isDirectory()) throw new Error('MCP root must be a directory.');
  const handle = serveStdio(() => createMcpServer(resolved), {
    onerror: (error) => log(`mikeops-guard MCP transport error: ${redactSecrets(error.message)}\n`),
  });
  log(`MikeOps Guard MCP server confined to ${resolved}\n`);
  return handle;
}

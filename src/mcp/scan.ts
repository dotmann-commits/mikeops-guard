import { Buffer } from 'node:buffer';
import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { toolVersion } from '../cli/version.js';
import { loadConfig } from '../config/load.js';
import { configSchema } from '../config/schema.js';
import { execCommand } from '../core/exec.js';
import { runScan } from '../core/run.js';
import { resolveBinary } from '../core/tools.js';
import type { Finding, ScannerOutcome, Severity } from '../core/types.js';
import { aiSupplyChainScanner } from '../scanners/ai-supply-chain/index.js';
import { appSecurityScanner } from '../scanners/app-security/index.js';
import { SCANNERS } from '../scanners/registry.js';
import { workflowAuditScanner } from '../scanners/workflow-audit/index.js';

export interface McpScanInput {
  path: string;
  failOn: Severity | 'none';
  maxFindings: number;
  mode: 'fast' | 'full';
}

export interface McpFinding {
  fingerprint: string;
  scanner: string;
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  file?: string;
  line?: number;
  remediation?: string;
}

export interface McpScanOutput {
  status: 'passed' | 'failed' | 'incomplete';
  passed: boolean;
  target: string;
  mode: 'fast' | 'full';
  durationMs: number;
  totalFindings: number;
  truncated: boolean;
  summary: Record<string, number>;
  coverageGaps: { scanner: string; reason: string }[];
  findings: McpFinding[];
}

const FAST_SCANNERS = [workflowAuditScanner, appSecurityScanner, aiSupplyChainScanner] as const;
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_FIELD_CHARS = 2_000;

function insideRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export async function resolveTargetWithinRoot(serverRoot: string, requestedPath: string): Promise<string> {
  if (!requestedPath || path.isAbsolute(requestedPath)) throw new Error('Scan path must be a relative path inside the configured root.');
  const root = await realpath(serverRoot);
  const requested = path.resolve(root, requestedPath);
  let target: string;
  try {
    target = await realpath(requested);
  } catch {
    throw new Error(`Scan path does not exist: ${requestedPath}`);
  }
  if (!insideRoot(root, target)) throw new Error('Scan path escapes the configured root.');
  if (!(await stat(target)).isDirectory()) throw new Error('Scan path must identify a directory.');
  return target;
}

function clip(value: string): string {
  return value.length <= MAX_FIELD_CHARS ? value : `${value.slice(0, MAX_FIELD_CHARS - 1)}…`;
}

function mcpFinding(finding: Finding): McpFinding {
  return {
    fingerprint: finding.fingerprint,
    scanner: finding.scanner,
    ruleId: finding.ruleId,
    severity: finding.severity,
    title: clip(finding.title),
    message: clip(finding.message),
    ...(finding.file ? { file: finding.file } : {}),
    ...(finding.line ? { line: finding.line } : {}),
    ...(finding.remediation ? { remediation: clip(finding.remediation) } : {}),
  };
}

function coverageGaps(outcomes: readonly ScannerOutcome[]): { scanner: string; reason: string }[] {
  return outcomes
    .filter((outcome) => outcome.incomplete)
    .map((outcome) => ({ scanner: outcome.scanner, reason: clip(outcome.reason ?? 'scanner did not complete') }));
}

function boundOutput(output: McpScanOutput): McpScanOutput {
  while (output.findings.length > 0 && Buffer.byteLength(JSON.stringify(output)) > MAX_RESPONSE_BYTES) {
    output.findings.pop();
    output.truncated = true;
  }
  if (Buffer.byteLength(JSON.stringify(output)) > MAX_RESPONSE_BYTES) {
    throw new Error('Scan summary exceeds the MCP response limit. Narrow the path and try again.');
  }
  return output;
}

export async function scanRepositoryForMcp(serverRoot: string, input: McpScanInput): Promise<McpScanOutput> {
  const root = await realpath(serverRoot);
  const target = await resolveTargetWithinRoot(root, input.path);
  const scanners = input.mode === 'fast' ? FAST_SCANNERS : SCANNERS;
  const config = input.mode === 'fast'
    ? configSchema.parse({ failOn: input.failOn })
    : { ...(await loadConfig({ root: target, cwd: root })).config, failOn: input.failOn };
  const report = await runScan({
    root: target,
    config,
    scanners,
    exec: execCommand,
    resolveBinary: (name) => resolveBinary(name, process.env.PATH ?? ''),
    toolVersion: toolVersion(),
  });
  const limit = Math.max(1, Math.min(100, input.maxFindings));
  const findings = report.findings.slice(0, limit).map(mcpFinding);
  return boundOutput({
    status: report.status,
    passed: report.passed,
    target: path.relative(root, target) || '.',
    mode: input.mode,
    durationMs: report.durationMs,
    totalFindings: report.findings.length,
    truncated: findings.length < report.findings.length,
    summary: report.summary,
    coverageGaps: coverageGaps(report.scanners),
    findings,
  });
}

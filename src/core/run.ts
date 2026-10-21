import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { GuardConfig } from '../config/schema.js';
import { discoverFiles, isGitRepository } from './discover.js';
import { CancelledError, errorMessage, ToolMissingError } from './errors.js';
import type { ExecFn } from './exec.js';
import { fingerprintAll } from './fingerprint.js';
import { applyPolicy, countBySeverity, meetsThreshold } from './policy.js';
import { redactOptional, redactSecrets } from './redact.js';
import type { ScanContext, Scanner, SkippedFile } from './scanner.js';
import { installHint, type BinaryResolver } from './tools.js';
import type { Finding, NewFinding, Report, ScannerOutcome } from './types.js';

export interface RunScanOptions {
  root: string;
  config: GuardConfig;
  scanners: readonly Scanner[];
  exec: ExecFn;
  resolveBinary: BinaryResolver;
  toolVersion: string;
  now?: () => Date;
  /** Aborting stops every running scanner. runScan then rejects with CancelledError instead of returning a partial report. */
  signal?: AbortSignal;
}

type BaseContext = Omit<ScanContext, 'binary' | 'skipFile'>;

/** Enough to explain a partial scan without letting a hostile repository bloat the report. */
const MAX_LISTED_SKIPPED_FILES = 20;

interface ScannerRun {
  outcome: ScannerOutcome;
  findings: Finding[];
}

export async function runScan(options: RunScanOptions): Promise<Report> {
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const { root, config } = options;
  const signal = options.signal ?? new AbortController().signal;
  if (signal.aborted) throw new CancelledError();
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'mikeops-guard-'));

  try {
    const baseContext: BaseContext = {
      root,
      config,
      files: await discoverFiles(root, config.exclude),
      isGitRepo: await isGitRepository(root),
      tempDir,
      timeoutMs: config.timeoutSeconds * 1000,
      exec: options.exec,
      signal,
    };
    const enabled = options.scanners.filter((s) => config.scanners[s.id].enabled);
    const ran = await runGrouped(
      enabled,
      (scanner) => scanner.tool(config) ?? scanner.id,
      (scanner) => runOne(scanner, baseContext, options),
    );
    // A cancelled run is not a result: failed scanners here mean "interrupted", not "broken", so no report is built.
    if (signal.aborted) throw new CancelledError();
    // Disabled scanners are reported too, so a policy file cannot narrow a scan without it showing.
    const runs = options.scanners.map(
      (scanner) =>
        ran.find((r) => r.outcome.scanner === scanner.id) ?? {
          outcome: {
            scanner: scanner.id,
            title: scanner.title,
            status: 'skipped' as const,
            durationMs: 0,
            findingCount: 0,
            incomplete: true,
            reason: 'disabled by the config or by --only/--skip',
          },
          findings: [],
        },
    );

    const { kept, ignored } = applyPolicy(
      runs.flatMap((r) => r.findings),
      config,
    );
    const finishedAt = now();
    const passed = !kept.some((f) => meetsThreshold(f.severity, config.failOn));
    const status = !passed ? 'failed' : runs.some((r) => r.outcome.incomplete) ? 'incomplete' : 'passed';
    return {
      schemaVersion: 1,
      tool: { name: 'mikeops-guard', version: options.toolVersion },
      target: root,
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      failOn: config.failOn,
      passed,
      status,
      summary: { ...countBySeverity(kept), total: kept.length, ignored },
      scanners: runs.map((r) => r.outcome),
      findings: kept,
    };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

/**
 * Scanners that share a binary run one after another (Trivy locks its cache),
 * while different binaries run in parallel. Output order follows the input order.
 */
async function runGrouped(
  scanners: readonly Scanner[],
  groupKey: (s: Scanner) => string,
  run: (s: Scanner) => Promise<ScannerRun>,
): Promise<ScannerRun[]> {
  const groups = new Map<string, Scanner[]>();
  for (const scanner of scanners) {
    const key = groupKey(scanner);
    groups.set(key, [...(groups.get(key) ?? []), scanner]);
  }
  const results = new Map<Scanner, ScannerRun>();
  await Promise.all(
    [...groups.values()].map(async (group) => {
      for (const scanner of group) results.set(scanner, await run(scanner));
    }),
  );
  return scanners.flatMap((s) => results.get(s) ?? []);
}

async function runOne(scanner: Scanner, base: BaseContext, options: RunScanOptions): Promise<ScannerRun> {
  const started = Date.now();
  const outcome = (fields: Omit<ScannerOutcome, 'scanner' | 'title' | 'durationMs' | 'incomplete'>, incomplete: boolean): ScannerOutcome => ({
    scanner: scanner.id,
    title: scanner.title,
    durationMs: Date.now() - started,
    incomplete,
    ...fields,
  });

  if (base.signal.aborted) throw new CancelledError();
  const tool = scanner.tool(base.config);
  let binary: string | undefined;
  if (tool) {
    binary = options.resolveBinary(tool) ?? undefined;
    if (!binary) {
      const status = base.config.requireTools ? 'failed' : 'skipped';
      return {
        outcome: outcome({ status, findingCount: 0, reason: `${tool} is not installed`, installHint: installHint(tool) }, true),
        findings: [],
      };
    }
  }

  const skipped: SkippedFile[] = [];
  const skipFile = (file: SkippedFile): void => void skipped.push(file);
  const ctx: ScanContext = binary ? { ...base, binary, skipFile } : { ...base, skipFile };
  const skipReason = scanner.skipReason(ctx);
  if (skipReason) return { outcome: outcome({ status: 'skipped', findingCount: 0, reason: skipReason }, false), findings: [] };

  try {
    const findings = fingerprintAll((await scanner.run(ctx)).map(redactFinding));
    return { outcome: outcome({ status: 'ok', findingCount: findings.length, ...skippedFields(skipped) }, skipped.some((s) => s.affectsCoverage)), findings };
  } catch (error) {
    if (error instanceof CancelledError) throw error;
    const hint = error instanceof ToolMissingError && tool ? installHint(tool) : undefined;
    return {
      outcome: outcome({ status: 'failed', findingCount: 0, reason: redactSecrets(errorMessage(error)), ...(hint ? { installHint: hint } : {}) }, true),
      findings: [],
    };
  }
}

function skippedFields(skipped: readonly SkippedFile[]): Pick<ScannerOutcome, 'reason' | 'skippedFiles' | 'skippedFileCount'> {
  if (skipped.length === 0) return {};
  const listed = skipped.slice(0, MAX_LISTED_SKIPPED_FILES).map(({ file, reason }) => ({ file: redactSecrets(file), reason }));
  const names = listed.slice(0, 3).map((s) => s.file).join(', ');
  const more = skipped.length > 3 ? ` and ${skipped.length - 3} more` : '';
  return {
    reason: `${skipped.length} file(s) not checked: ${names}${more}`,
    skippedFiles: listed,
    skippedFileCount: skipped.length,
  };
}

/** Scanner text can quote what it found (a workflow line, a config value), so credential formats are removed first. */
function redactFinding(finding: NewFinding): NewFinding {
  const remediation = redactOptional(finding.remediation);
  return {
    ...finding,
    title: redactSecrets(finding.title),
    message: redactSecrets(finding.message),
    ...(remediation !== undefined ? { remediation } : {}),
  };
}

import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { GuardConfig } from '../config/schema.js';
import { discoverFiles, isGitRepository } from './discover.js';
import { errorMessage, ToolMissingError } from './errors.js';
import type { ExecFn } from './exec.js';
import { withFingerprint } from './fingerprint.js';
import { applyPolicy, countBySeverity, meetsThreshold } from './policy.js';
import type { ScanContext, Scanner } from './scanner.js';
import { installHint, type BinaryResolver } from './tools.js';
import type { Finding, Report, ScannerOutcome } from './types.js';

export interface RunScanOptions {
  root: string;
  config: GuardConfig;
  scanners: readonly Scanner[];
  exec: ExecFn;
  resolveBinary: BinaryResolver;
  toolVersion: string;
  now?: () => Date;
}

interface ScannerRun {
  outcome: ScannerOutcome;
  findings: Finding[];
}

export async function runScan(options: RunScanOptions): Promise<Report> {
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const { root, config } = options;
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'mikeops-guard-'));

  try {
    const baseContext: Omit<ScanContext, 'binary'> = {
      root,
      config,
      files: await discoverFiles(root, config.exclude),
      isGitRepo: await isGitRepository(root),
      tempDir,
      timeoutMs: config.timeoutSeconds * 1000,
      exec: options.exec,
    };
    const enabled = options.scanners.filter((s) => config.scanners[s.id].enabled);
    const runs = await runGrouped(
      enabled,
      (scanner) => scanner.tool(config) ?? scanner.id,
      (scanner) => runOne(scanner, baseContext, options),
    );

    const { kept, ignored } = applyPolicy(
      runs.flatMap((r) => r.findings),
      config,
    );
    const finishedAt = now();
    return {
      schemaVersion: 1,
      tool: { name: 'mikeops-guard', version: options.toolVersion },
      target: root,
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      failOn: config.failOn,
      passed: !kept.some((f) => meetsThreshold(f.severity, config.failOn)),
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

async function runOne(scanner: Scanner, base: Omit<ScanContext, 'binary'>, options: RunScanOptions): Promise<ScannerRun> {
  const started = Date.now();
  const outcome = (fields: Omit<ScannerOutcome, 'scanner' | 'title' | 'durationMs'>): ScannerOutcome => ({
    scanner: scanner.id,
    title: scanner.title,
    durationMs: Date.now() - started,
    ...fields,
  });

  const tool = scanner.tool(base.config);
  let binary: string | undefined;
  if (tool) {
    binary = options.resolveBinary(tool) ?? undefined;
    if (!binary) {
      const status = base.config.requireTools ? 'failed' : 'skipped';
      return {
        outcome: outcome({ status, findingCount: 0, reason: `${tool} is not installed`, installHint: installHint(tool) }),
        findings: [],
      };
    }
  }

  const ctx: ScanContext = binary ? { ...base, binary } : base;
  const skipReason = scanner.skipReason(ctx);
  if (skipReason) return { outcome: outcome({ status: 'skipped', findingCount: 0, reason: skipReason }), findings: [] };

  try {
    const findings = (await scanner.run(ctx)).map(withFingerprint);
    return { outcome: outcome({ status: 'ok', findingCount: findings.length }), findings };
  } catch (error) {
    const hint = error instanceof ToolMissingError && tool ? installHint(tool) : undefined;
    return {
      outcome: outcome({ status: 'failed', findingCount: 0, reason: errorMessage(error), ...(hint ? { installHint: hint } : {}) }),
      findings: [],
    };
  }
}

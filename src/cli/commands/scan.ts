import { mkdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { loadConfig } from '../../config/load.js';
import { UsageError } from '../../core/errors.js';
import { execCommand } from '../../core/exec.js';
import { exitCodeFor } from '../../core/policy.js';
import { runScan } from '../../core/run.js';
import type { Scanner } from '../../core/scanner.js';
import { resolveBinary, type BinaryResolver } from '../../core/tools.js';
import type { Report } from '../../core/types.js';
import { explainFindings, OllamaClient } from '../../explain/ollama.js';
import { renderConsole } from '../../report/console.js';
import { renderHtml } from '../../report/html.js';
import { renderJson } from '../../report/json.js';
import { terminalSafe } from '../../report/terminal.js';
import { SCANNERS } from '../../scanners/registry.js';
import type { ScanOptions } from '../args.js';
import type { CliIo } from '../io.js';
import { toolVersion } from '../version.js';
import { applyCliOverrides } from './overrides.js';

export interface ScanDependencies {
  scanners?: readonly Scanner[];
  resolveBinary?: BinaryResolver;
}

async function resolveTarget(cwd: string, target: string): Promise<string> {
  const root = path.resolve(cwd, target);
  const info = await stat(root).catch(() => null);
  if (!info) throw new UsageError(`Target path does not exist: ${root}`);
  if (!info.isDirectory()) throw new UsageError(`Target path is not a directory: ${root}`);
  return root;
}

async function writeReport(cwd: string, file: string, content: string): Promise<string> {
  const destination = path.resolve(cwd, file);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, content, 'utf8');
  return destination;
}

export async function scanCommand(options: ScanOptions, io: CliIo, deps: ScanDependencies = {}): Promise<number> {
  const root = await resolveTarget(io.cwd, options.path);
  const loaded = await loadConfig({ root, cwd: io.cwd, ...(options.config ? { explicitPath: options.config } : {}) });
  const config = applyCliOverrides(loaded.config, options);
  // With --json - the JSON owns stdout, so human output moves to stderr.
  const log = options.json === '-' ? io.stderr : io.stdout;

  if (!options.quiet) log(loaded.source ? `Using config ${terminalSafe(loaded.source)}\n` : 'No config file found, using defaults\n');
  for (const warning of loaded.warnings) io.stderr(`Warning: ${terminalSafe(warning)}\n`); // even with --quiet

  let report: Report = await runScan({
    root,
    config,
    scanners: deps.scanners ?? SCANNERS,
    exec: execCommand,
    resolveBinary: deps.resolveBinary ?? ((name) => resolveBinary(name, io.env.PATH ?? '')),
    toolVersion: toolVersion(),
  });

  if (config.explain.enabled && report.findings.length > 0) {
    if (!options.quiet) log(`Explaining up to ${config.explain.maxFindings} finding(s) with ${config.explain.model} on ${config.explain.host}\n`);
    const client = new OllamaClient({
      host: config.explain.host,
      model: config.explain.model,
      timeoutMs: config.explain.timeoutSeconds * 1000,
    });
    const result = await explainFindings(report, client, config.explain.model, config.explain.maxFindings);
    report = { ...report, findings: result.findings, explain: result.outcome };
  }

  if (options.json === '-') io.stdout(renderJson(report));
  else if (options.json) log(`JSON report: ${await writeReport(io.cwd, options.json, renderJson(report))}\n`);
  if (options.html) log(`HTML report: ${await writeReport(io.cwd, options.html, renderHtml(report))}\n`);

  const text = renderConsole(report, { color: options.color, maxFindings: options.quiet ? 0 : options.maxFindings });
  log(options.quiet ? text.split('\n').filter((l) => l.startsWith('Summary') || l.startsWith('Result')).join('\n') + '\n' : `\n${text}`);
  if (report.explain?.reason && !options.quiet) log(`Explain: ${terminalSafe(report.explain.reason)}\n`);
  return exitCodeFor(report);
}

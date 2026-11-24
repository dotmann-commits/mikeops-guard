import { parseArgs } from 'node:util';
import { UsageError } from '../core/errors.js';
import { SCANNER_IDS, SEVERITIES, type ScannerId, type Severity } from '../core/types.js';

export type Command = 'scan' | 'hook' | 'mcp' | 'doctor' | 'init' | 'help' | 'version';

export interface ScanOptions {
  path: string;
  config?: string;
  failOn?: Severity | 'none';
  only?: ScannerId[];
  skip?: ScannerId[];
  json?: string;
  html?: string;
  sarif?: string;
  markdown?: string;
  baseline?: string;
  changedSince?: string;
  explain: boolean;
  model?: string;
  requireTools: boolean;
  maxFindings: number;
  color: boolean;
  quiet: boolean;
}

export interface HookOptions {
  path: string;
  agent: boolean;
  failOn: Severity | 'none';
}

export interface InitOptions {
  claudeHook: boolean;
  cursorHook: boolean;
  preCommit: boolean;
  skill: boolean;
}

export type ParsedArgs =
  | { command: Exclude<Command, 'scan' | 'hook' | 'mcp' | 'init'> }
  | { command: 'init'; options: InitOptions }
  | { command: 'hook'; options: HookOptions }
  | { command: 'mcp'; root: string }
  | { command: 'scan'; options: ScanOptions };

const DEFAULT_MAX_FINDINGS = 25;
const COMMANDS = new Set<string>(['scan', 'hook', 'mcp', 'doctor', 'init', 'help']);

function parseScannerList(value: string | undefined, flag: string): ScannerId[] | undefined {
  if (value === undefined) return undefined;
  const ids = value.split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = ids.filter((id) => !(SCANNER_IDS as readonly string[]).includes(id));
  if (unknown.length > 0) {
    throw new UsageError(`Unknown scanner in ${flag}: ${unknown.join(', ')}. Valid: ${SCANNER_IDS.join(', ')}`);
  }
  return ids as ScannerId[];
}

function parseFailOn(value: string | undefined): Severity | 'none' | undefined {
  if (value === undefined) return undefined;
  const allowed: readonly string[] = [...SEVERITIES, 'none'];
  if (!allowed.includes(value)) throw new UsageError(`--fail-on must be one of: ${allowed.join(', ')}`);
  return value as Severity | 'none';
}

function parsePositiveInt(value: string | undefined, flag: string, fallback: number): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new UsageError(`${flag} must be a whole number`);
  return n;
}

export function parseCliArgs(argv: readonly string[], env: NodeJS.ProcessEnv, isTty: boolean): ParsedArgs {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      strict: true,
      options: {
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
        config: { type: 'string', short: 'c' },
        'fail-on': { type: 'string' },
        only: { type: 'string' },
        skip: { type: 'string' },
        json: { type: 'string' },
        html: { type: 'string' },
        sarif: { type: 'string' },
        markdown: { type: 'string' },
        baseline: { type: 'string' },
        'changed-since': { type: 'string' },
        explain: { type: 'boolean' },
        model: { type: 'string' },
        'require-tools': { type: 'boolean' },
        'max-findings': { type: 'string' },
        'no-color': { type: 'boolean' },
        quiet: { type: 'boolean', short: 'q' },
        agent: { type: 'boolean' },
        'claude-hook': { type: 'boolean' },
        'cursor-hook': { type: 'boolean' },
        'pre-commit': { type: 'boolean' },
        skill: { type: 'boolean' },
      },
    });
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }

  const { values, positionals } = parsed;
  if (values.version) return { command: 'version' };
  if (values.help) return { command: 'help' };

  const [first, ...rest] = positionals;
  const command = first ?? 'help';
  if (!COMMANDS.has(command)) throw new UsageError(`Unknown command "${command}". Run "mikeops-guard --help".`);
  if (command === 'mcp') {
    if (rest.length > 1) throw new UsageError('mcp takes at most one root path');
    return { command: 'mcp', root: rest[0] ?? '.' };
  }
  if (command === 'hook') {
    if (rest.length > 1) throw new UsageError('hook takes at most one path');
    return {
      command: 'hook',
      options: { path: rest[0] ?? '.', agent: values.agent ?? false, failOn: parseFailOn(values['fail-on']) ?? 'high' },
    };
  }
  if (command === 'init') {
    if (rest.length > 0) throw new UsageError('"init" does not take arguments');
    return {
      command: 'init',
      options: {
        claudeHook: values['claude-hook'] ?? false,
        cursorHook: values['cursor-hook'] ?? false,
        preCommit: values['pre-commit'] ?? false,
        skill: values.skill ?? false,
      },
    };
  }
  if (command !== 'scan') {
    if (rest.length > 0) throw new UsageError(`"${command}" does not take arguments`);
    return { command: command as Exclude<Command, 'scan' | 'hook' | 'mcp' | 'init'> };
  }
  if (rest.length > 1) throw new UsageError('scan takes at most one path');

  const options: ScanOptions = {
    path: rest[0] ?? '.',
    explain: values.explain ?? false,
    requireTools: values['require-tools'] ?? false,
    maxFindings: parsePositiveInt(values['max-findings'], '--max-findings', DEFAULT_MAX_FINDINGS),
    color: isTty && !values['no-color'] && env.NO_COLOR === undefined,
    quiet: values.quiet ?? false,
  };
  const failOn = parseFailOn(values['fail-on']);
  const only = parseScannerList(values.only, '--only');
  const skip = parseScannerList(values.skip, '--skip');
  if (failOn) options.failOn = failOn;
  if (only) options.only = only;
  if (skip) options.skip = skip;
  if (values.config) options.config = values.config;
  if (values.json) options.json = values.json;
  if (values.html) options.html = values.html;
  if (values.sarif) options.sarif = values.sarif;
  if (values.markdown) options.markdown = values.markdown;
  if (values.baseline) options.baseline = values.baseline;
  if (values['changed-since']) options.changedSince = values['changed-since'];
  if (values.model) options.model = values.model;
  const stdoutReports = [options.json, options.sarif, options.markdown].filter((file) => file === '-');
  if (stdoutReports.length > 1) throw new UsageError('Only one of --json, --sarif or --markdown may write to stdout');
  return { command: 'scan', options };
}

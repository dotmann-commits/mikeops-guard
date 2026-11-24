import path from 'node:path';
import { FILE_CONCURRENCY, mapLimit } from '../../core/concurrency.js';
import { readTextFile } from '../../core/files.js';
import type { Scanner } from '../../core/scanner.js';
import type { NewFinding } from '../../core/types.js';

const HIDDEN_CONTROL = /[\u202A-\u202E\u2066-\u2069]/g;
// ZWNJ/ZWJ are intentionally excluded: they are legitimate in many writing systems and emoji sequences.
const INVISIBLE_CONTROL = /[\u200B\u2060\uFEFF\u{E0000}-\u{E007F}]/gu;
const SHELLS = new Set(['bash', 'sh', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe']);
const SECRET_NAME = /(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)/i;
const SECRET_HEADER = /^(?:authorization|proxy-authorization|x-api-key|api-key)$/i;
const ENV_FALLBACK = /process\.env\.([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*(['"`])([^'"`\r\n]{1,128})\2/g;
const PUBLIC_AI_KEY = /(?:import\.meta\.env|process\.env)\.((?:VITE_|NEXT_PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)[A-Z0-9_]*(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE_AI|MISTRAL|COHERE)[A-Z0-9_]*(?:API_)?KEY[A-Z0-9_]*)/g;

function lineStarts(source: string): number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index++) {
    if (source[index] === '\n') starts.push(index + 1);
  }
  return starts;
}

function lineAt(starts: readonly number[], index: number): number {
  let low = 0;
  let high = starts.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if ((starts[middle] ?? 0) <= index) low = middle + 1;
    else high = middle;
  }
  return low;
}

function finding(fields: Omit<NewFinding, 'scanner' | 'category' | 'references'>): NewFinding {
  return { scanner: 'ai-supply-chain', category: 'application', references: [], ...fields };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function serverLine(source: string, starts: readonly number[], name: string): number | undefined {
  const index = source.indexOf(JSON.stringify(name));
  return index >= 0 ? lineAt(starts, index) : undefined;
}

function packageArgument(command: string, args: readonly unknown[]): string | undefined {
  if (command !== 'npx' && command !== 'npx.cmd' && command !== 'uvx') return undefined;
  return args.find((arg): arg is string => typeof arg === 'string' && !arg.startsWith('-'));
}

function isPinnedPackage(command: string, specifier: string): boolean {
  if (/^(?:\.|\/|file:|https?:)/.test(specifier)) return true;
  if (command === 'uvx') return /==\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(specifier);
  const versionAt = specifier.lastIndexOf('@');
  return versionAt > 0 && /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(specifier.slice(versionAt + 1));
}

function isEnvironmentReference(value: string): boolean {
  return value === '' || /^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})$/.test(value);
}

function stripJsonComments(source: string): string {
  let output = '';
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < source.length; index++) {
    const character = source[index] ?? '';
    const next = source[index + 1] ?? '';
    if (lineComment) {
      if (character === '\n' || character === '\r') {
        lineComment = false;
        output += character;
      } else output += ' ';
      continue;
    }
    if (blockComment) {
      if (character === '*' && next === '/') {
        output += '  ';
        index++;
        blockComment = false;
      } else output += character === '\n' || character === '\r' ? character : ' ';
      continue;
    }
    if (inString) {
      output += character;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      output += character;
    } else if (character === '/' && next === '/') {
      output += '  ';
      index++;
      lineComment = true;
    } else if (character === '/' && next === '*') {
      output += '  ';
      index++;
      blockComment = true;
    } else output += character;
  }
  return output;
}

function removeTrailingCommas(source: string): string {
  let output = '';
  let inString = false;
  let escaped = false;
  for (let index = 0; index < source.length; index++) {
    const character = source[index] ?? '';
    if (inString) {
      output += character;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      output += character;
      continue;
    }
    if (character === ',') {
      let next = index + 1;
      while (/\s/.test(source[next] ?? '')) next++;
      output += source[next] === '}' || source[next] === ']' ? ' ' : character;
    } else output += character;
  }
  return output;
}

function parseJsonc(source: string): unknown {
  return JSON.parse(removeTrailingCommas(stripJsonComments(source)));
}

export function mcpConfigFindings(file: string, source: string): NewFinding[] {
  let parsed: unknown;
  try {
    parsed = parseJsonc(source);
  } catch {
    return [finding({
      ruleId: 'mcp-config-parse-error',
      title: 'MCP configuration could not be parsed',
      severity: 'low',
      file,
      message: 'This MCP configuration is not valid JSON, so its server launch commands could not be audited.',
      remediation: 'Fix the JSON syntax and run MikeOps Guard again.',
    })];
  }

  if (!isRecord(parsed)) return [];
  const serverGroups = [parsed.mcpServers, parsed.servers].filter(isRecord);
  if (serverGroups.length === 0) return [];
  const findings: NewFinding[] = [];
  const starts = lineStarts(source);
  for (const [name, server] of serverGroups.flatMap((group) => Object.entries(group))) {
    if (!isRecord(server)) continue;
    const commandValue = typeof server.command === 'string' ? server.command : '';
    const command = commandValue.split(/[\\/]/).at(-1)?.toLowerCase() ?? '';
    const args = Array.isArray(server.args) ? server.args : [];
    const line = serverLine(source, starts, name);
    const location = line === undefined ? { file } : { file, line };

    if (SHELLS.has(command)) {
      const switches = args.filter((arg): arg is string => typeof arg === 'string').map((arg) => arg.toLowerCase());
      const hasCommandString = ['cmd', 'cmd.exe'].includes(command)
        ? switches.includes('/c')
        : switches.some((arg) => arg === '-c' || arg === '-command');
      if (hasCommandString) {
        findings.push(finding({
          ruleId: 'mcp-shell-command',
          title: `MCP server "${name}" launches through a command shell`,
          severity: 'high',
          ...location,
          message: 'Shell command strings can run pipelines, substitutions and multiple commands when an MCP client starts the server.',
          remediation: 'Launch a fixed executable directly and pass each argument separately. Avoid sh -c, bash -c, cmd /c and PowerShell command strings.',
        }));
      }
    }

    const packageName = packageArgument(command, args);
    if (packageName && !isPinnedPackage(command, packageName)) {
      findings.push(finding({
        ruleId: 'mcp-unpinned-package',
        title: `MCP server "${name}" installs an unpinned package`,
        severity: 'medium',
        ...location,
        message: `${command} resolves the package from a mutable registry version when the MCP client starts it. A future release can execute without review.`,
        remediation: command === 'uvx' ? 'Pin the package with ==x.y.z.' : 'Pin the package with @x.y.z.',
      }));
    }

    for (const [fieldGroup, values] of [['environment variable', server.env], ['HTTP header', server.headers]] as const) {
      if (!isRecord(values)) continue;
      for (const [variable, value] of Object.entries(values)) {
        const sensitive = fieldGroup === 'HTTP header' ? SECRET_HEADER.test(variable) : SECRET_NAME.test(variable);
        if (!sensitive || typeof value !== 'string' || isEnvironmentReference(value)) continue;
        findings.push(finding({
          ruleId: 'mcp-literal-secret',
          title: `MCP server "${name}" contains a literal secret`,
          severity: 'high',
          ...location,
          message: `${fieldGroup === 'HTTP header' ? 'HTTP header' : 'Environment variable'} ${variable} contains a literal value in MCP configuration. The value is intentionally omitted from this report.`,
          remediation: `Replace the value with an environment reference such as \${${variable}} and rotate the exposed credential.`,
        }));
      }
    }
  }
  return findings;
}

export function instructionFindings(file: string, source: string): NewFinding[] {
  const starts = lineStarts(source);
  const matches = [
    ...[...source.matchAll(HIDDEN_CONTROL)].map((match) => ({ match, kind: 'bidi' as const })),
    ...[...source.matchAll(INVISIBLE_CONTROL)].map((match) => ({ match, kind: 'invisible' as const })),
  ].sort((left, right) => left.match.index - right.match.index);
  return matches.map(({ match, kind }) => finding({
    ruleId: kind === 'bidi' ? 'hidden-unicode-control' : 'invisible-unicode-control',
    title: kind === 'bidi'
      ? 'AI instruction file contains a hidden bidirectional control'
      : 'AI instruction file contains an invisible Unicode control',
    severity: 'high',
    file,
    line: lineAt(starts, match.index),
    message: kind === 'bidi'
      ? 'A bidirectional Unicode control can make displayed text differ from the order that an agent or parser reads.'
      : 'A zero-width character or Unicode Tag can hide instructions from reviewers while remaining readable to an agent.',
    remediation: 'Remove the hidden control and rewrite the affected line using visible plain text.',
  }));
}

export function claudeSettingsFindings(file: string, source: string): NewFinding[] {
  let parsed: unknown;
  try {
    parsed = parseJsonc(source);
  } catch {
    return [finding({
      ruleId: 'claude-settings-parse-error',
      title: 'Claude settings could not be parsed',
      severity: 'low',
      file,
      message: 'This Claude settings file is not valid JSONC, so hooks could not be audited.',
      remediation: 'Fix the JSONC syntax and run MikeOps Guard again.',
    })];
  }
  if (!isRecord(parsed) || !isRecord(parsed.hooks)) return [];
  const findings: NewFinding[] = [];
  const starts = lineStarts(source);
  const visit = (value: unknown, key?: string): void => {
    if (key === 'matcher' && typeof value === 'string' && /\bBash\s*\(\s*\*\s*\)/i.test(value)) {
      const index = source.indexOf(JSON.stringify(value));
      findings.push(finding({
        ruleId: 'claude-wildcard-bash-hook',
        title: 'Claude hook matches every Bash command',
        severity: 'high',
        file,
        ...(index >= 0 ? { line: lineAt(starts, index) } : {}),
        message: 'A Bash(*) hook runs for every shell command an agent attempts, creating a broad interception and command-execution boundary.',
        remediation: 'Replace Bash(*) with the narrowest command matcher required and keep hook commands fixed, reviewed and non-secret.',
      }));
      return;
    }
    if (Array.isArray(value)) for (const item of value) visit(item);
    else if (isRecord(value)) for (const [childKey, child] of Object.entries(value)) visit(child, childKey);
  };
  visit(parsed.hooks);
  return findings;
}

export function aiSourceFindings(file: string, source: string): NewFinding[] {
  if (/(?:^|\/)(?:test|tests|__tests__|fixtures)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(file)) return [];
  const findings: NewFinding[] = [];
  const starts = lineStarts(source);
  for (const match of source.matchAll(ENV_FALLBACK)) {
    findings.push(finding({
      ruleId: 'hardcoded-secret-fallback',
      title: `${match[1] ?? 'A secret'} falls back to a hardcoded value`,
      severity: 'high',
      file,
      line: lineAt(starts, match.index),
      message: 'A missing environment secret silently enables a literal fallback. The fallback value is intentionally omitted from this report.',
      remediation: 'Fail startup when the secret is missing and load development credentials from an ignored local environment file.',
    }));
  }
  for (const match of source.matchAll(PUBLIC_AI_KEY)) {
    findings.push(finding({
      ruleId: 'public-ai-api-key',
      title: `${match[1] ?? 'An AI API key'} would be shipped to every browser`,
      severity: 'critical',
      file,
      line: lineAt(starts, match.index),
      message: 'This public environment prefix exposes an AI provider key in the frontend bundle, allowing anyone to spend the account quota.',
      remediation: 'Move AI provider calls behind a server route and keep the key in a server-only environment variable. Rotate it if deployed.',
    }));
  }
  return findings;
}

const MAX_AI_FILE_BYTES = 512 * 1024;

export const aiSupplyChainScanner: Scanner = {
  id: 'ai-supply-chain',
  title: 'AI agent and MCP supply-chain security',
  category: 'application',
  tool: () => null,
  skipReason: (ctx) => {
    const files = ctx.files;
    return files.mcpConfigs.length + files.aiInstructionFiles.length + files.sourceFiles.length === 0
      ? 'no MCP configuration, AI instructions or JavaScript/TypeScript source found'
      : null;
  },
  async run(ctx) {
    const scan = async (
      files: readonly string[],
      affectsCoverage: boolean,
      check: (file: string, source: string) => NewFinding[],
    ): Promise<NewFinding[][]> => mapLimit(files, FILE_CONCURRENCY, async (file) => {
      const read = await readTextFile(path.join(ctx.root, file), MAX_AI_FILE_BYTES);
      if (!read.ok) {
        ctx.skipFile({ file, reason: read.reason, affectsCoverage });
        return [];
      }
      return check(file, read.text);
    });

    const [configs, instructions, sources] = await Promise.all([
      scan(ctx.files.mcpConfigs, true, (file, source) => [
        ...instructionFindings(file, source),
        ...mcpConfigFindings(file, source),
      ]),
      scan(ctx.files.aiInstructionFiles, true, (file, source) => [
        ...instructionFindings(file, source),
        ...(/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i.test(file) ? claudeSettingsFindings(file, source) : []),
      ]),
      scan(ctx.files.sourceFiles, false, aiSourceFindings),
    ]);
    return [...configs.flat(), ...instructions.flat(), ...sources.flat()];
  },
};

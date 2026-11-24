import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { UsageError } from '../../core/errors.js';
import type { CliIo } from '../io.js';
import type { InitOptions } from '../args.js';

export const STARTER_CONFIG = `# MikeOps Guard configuration. Every key is optional.
# Docs: https://github.com/dotmann-commits/mikeops-guard#configuration

# Exit with code 1 when any finding is at or above this level.
# critical | high | medium | low | info | none
failOn: high

# Fail the run, instead of skipping, when a scanner binary is missing. Recommended in CI.
requireTools: false

timeoutSeconds: 300

# Paths to leave out of scans and reports (glob syntax: **, *, ?).
exclude:
  - "**/node_modules/**"
  - "**/vendor/**"

scanners:
  gitleaks:
    enabled: true
    mode: auto          # auto | git (full history) | dir (working tree only)
  workflow-audit:
    enabled: true
  actionlint:
    enabled: true
  hadolint:
    enabled: true
  trivy-config:
    enabled: true
  dependencies:
    enabled: true
    engine: osv-scanner # osv-scanner | trivy
  app-security:
    enabled: true       # env, Supabase and frontend checks for web apps
  ai-supply-chain:
    enabled: true       # MCP launchers, agent instructions and AI-app secret footguns

# Accepted risks. Match by rule id, "scanner:rule" or fingerprint, optionally limited to a path.
ignore: []
#  - rule: DL3008
#    path: docker/legacy.Dockerfile
#    reason: Pinned by the base image vendor

# Change the severity of a rule everywhere.
severityOverrides: {}
#  unpinned-action: high

# Optional plain-English explanations from a local Ollama model. Nothing leaves your machine.
explain:
  enabled: false
  host: http://127.0.0.1:11434
  model: llama3.2:3b
  maxFindings: 10
`;

const CLAUDE_HOOK_ENTRY = {
  matcher: 'Edit|Write',
  hooks: [{ type: 'command', command: 'mikeops-guard hook --agent', timeout: 30 }],
};
const CURSOR_HOOK_ENTRY = { command: 'mikeops-guard hook --agent', timeout: 30 };
const CLAUDE_HOOK_CONFIG = { hooks: { PostToolUse: [CLAUDE_HOOK_ENTRY] } };
const CURSOR_HOOK_CONFIG = { version: 1, hooks: { afterFileEdit: [CURSOR_HOOK_ENTRY] } };

const PRE_COMMIT_HOOK = `#!/bin/sh
# MikeOps Guard: silent when clean, compact directives when blocked.
exec mikeops-guard hook
`;

const AGENT_SKILL = `---
name: mikeops-guard
description: Run the repository security guard after changing workflows, migrations, application code, agent instructions or MCP configuration.
---

Run \`mikeops-guard hook\` from the repository root. If it prints directives, fix each cited file and line, then rerun until the command exits 0 with no output.
`;

async function writeSetupFile(file: string, content: string): Promise<boolean> {
  await mkdir(path.dirname(file), { recursive: true });
  try {
    await writeFile(file, content, { encoding: 'utf8', flag: 'wx' });
    return true;
  } catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST') {
      if (await readFile(file, 'utf8') === content) return false;
      throw new UsageError(`${file} already exists. Merge the MikeOps Guard integration manually so existing configuration is preserved.`);
    }
    throw error;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function containsGuardCommand(value: unknown): boolean {
  if (typeof value === 'string') return value === 'mikeops-guard hook --agent';
  if (Array.isArray(value)) return value.some(containsGuardCommand);
  return isRecord(value) && Object.values(value).some(containsGuardCommand);
}

async function mergeHookFile(
  file: string,
  event: string,
  entry: Record<string, unknown>,
  defaults: Record<string, unknown>,
): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  let existing: Record<string, unknown> = defaults;
  try {
    const parsed: unknown = JSON.parse(await readFile(file, 'utf8'));
    if (!isRecord(parsed)) throw new Error('root must be a JSON object');
    existing = parsed;
  } catch (error) {
    if (!(typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT')) {
      throw new UsageError(`${file} is not valid JSON and was not changed.`);
    }
  }
  const hooksValue = existing.hooks;
  if (hooksValue !== undefined && !isRecord(hooksValue)) throw new UsageError(`${file} has a non-object hooks field and was not changed.`);
  const hooks = hooksValue ?? {};
  const eventValue = hooks[event];
  if (eventValue !== undefined && !Array.isArray(eventValue)) throw new UsageError(`${file} has a non-array ${event} hook and was not changed.`);
  const entries: unknown[] = Array.isArray(eventValue) ? eventValue as unknown[] : [];
  const nextEntries = entries.some(containsGuardCommand) ? entries : [...entries, entry];
  await writeFile(file, `${JSON.stringify({ ...existing, hooks: { ...hooks, [event]: nextEntries } }, null, 2)}\n`, 'utf8');
}

export async function initCommand(io: CliIo, options: InitOptions): Promise<number> {
  const file = path.join(io.cwd, '.mikeops-guard.yml');
  const installGuardrails = options.claudeHook || options.cursorHook || options.preCommit || options.skill;
  try {
    // "wx" refuses to overwrite, so an existing policy is never lost.
    await writeFile(file, STARTER_CONFIG, { encoding: 'utf8', flag: 'wx' });
  } catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST') {
      if (!installGuardrails) throw new UsageError(`${file} already exists. Edit it or delete it first.`);
      // Integrations are additive; an existing repository policy remains authoritative.
    } else {
      throw error;
    }
  }
  if (!installGuardrails) {
    io.stdout(`Created ${file}\n`);
    return 0;
  }
  if (options.claudeHook) {
    const destination = path.join(io.cwd, '.claude/settings.json');
    await mergeHookFile(destination, 'PostToolUse', CLAUDE_HOOK_ENTRY, CLAUDE_HOOK_CONFIG);
    io.stdout(`Installed Claude Code hook: ${destination}\n`);
  }
  if (options.cursorHook) {
    const destination = path.join(io.cwd, '.cursor/hooks.json');
    await mergeHookFile(destination, 'afterFileEdit', CURSOR_HOOK_ENTRY, CURSOR_HOOK_CONFIG);
    io.stdout(`Installed Cursor hook: ${destination}\n`);
  }
  if (options.preCommit) {
    const destination = path.join(io.cwd, '.git/hooks/pre-commit');
    await writeSetupFile(destination, PRE_COMMIT_HOOK);
    await chmod(destination, 0o755);
    io.stdout(`Installed git pre-commit hook: ${destination}\n`);
  }
  if (options.skill) {
    const destination = path.join(io.cwd, '.claude/skills/mikeops-guard/SKILL.md');
    await writeSetupFile(destination, AGENT_SKILL);
    io.stdout(`Installed agent skill: ${destination}\n`);
  }
  return 0;
}

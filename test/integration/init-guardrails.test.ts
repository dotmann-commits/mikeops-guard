import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { CliIo } from '../../src/cli/io.js';
import { main } from '../../src/cli/main.js';

function capture(cwd: string): { io: CliIo; out: () => string; err: () => string } {
  let out = '';
  let err = '';
  return {
    io: { cwd, env: {}, isTty: false, stdout: (text) => void (out += text), stderr: (text) => void (err += text) },
    out: () => out,
    err: () => err,
  };
}

describe('guardrail initialization', () => {
  it('installs Claude, Cursor, pre-commit and skill integrations without hidden prompt cost', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-init-'));
    await mkdir(path.join(root, '.git/hooks'), { recursive: true });
    const run = capture(root);

    expect(await main(['init', '--claude-hook', '--cursor-hook', '--pre-commit', '--skill'], run.io)).toBe(0);
    expect(run.err()).toBe('');
    expect(await readFile(path.join(root, '.mikeops-guard.yml'), 'utf8')).toContain('ai-supply-chain:');

    const claude = JSON.parse(await readFile(path.join(root, '.claude/settings.json'), 'utf8')) as {
      hooks: { PostToolUse: Array<{ matcher: string; hooks: Array<{ command: string }> }> };
    };
    const claudeHook = claude.hooks.PostToolUse.at(0);
    expect(claudeHook).toMatchObject({ matcher: 'Edit|Write' });
    expect(claudeHook?.hooks.at(0)?.command).toBe('mikeops-guard hook --agent');

    const cursor = JSON.parse(await readFile(path.join(root, '.cursor/hooks.json'), 'utf8')) as {
      hooks: { afterFileEdit: Array<{ command: string }> };
    };
    expect(cursor.hooks.afterFileEdit.at(0)?.command).toBe('mikeops-guard hook --agent');

    const preCommit = await readFile(path.join(root, '.git/hooks/pre-commit'), 'utf8');
    expect(preCommit).toContain('exec mikeops-guard hook');
    expect((await stat(path.join(root, '.git/hooks/pre-commit'))).mode & 0o111).not.toBe(0);

    const skill = await readFile(path.join(root, '.claude/skills/mikeops-guard/SKILL.md'), 'utf8');
    expect(skill).toContain('mikeops-guard hook');
    expect(run.out()).toContain('Installed Claude Code hook');
  });

  it('merges hook installers into existing agent settings without discarding configuration', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-init-merge-'));
    await mkdir(path.join(root, '.claude'), { recursive: true });
    await mkdir(path.join(root, '.cursor'), { recursive: true });
    await writeFile(path.join(root, '.claude/settings.json'), JSON.stringify({ model: 'opus', hooks: { SessionStart: [{ matcher: 'startup', hooks: [] }] } }));
    await writeFile(path.join(root, '.cursor/hooks.json'), JSON.stringify({ version: 1, hooks: { stop: [{ command: './audit.sh' }] } }));
    const run = capture(root);

    expect(await main(['init', '--claude-hook', '--cursor-hook'], run.io)).toBe(0);
    const claude = JSON.parse(await readFile(path.join(root, '.claude/settings.json'), 'utf8')) as {
      model: string; hooks: { SessionStart: unknown[]; PostToolUse: unknown[] };
    };
    const cursor = JSON.parse(await readFile(path.join(root, '.cursor/hooks.json'), 'utf8')) as {
      hooks: { stop: unknown[]; afterFileEdit: unknown[] };
    };
    expect(claude.model).toBe('opus');
    expect(claude.hooks.SessionStart).toHaveLength(1);
    expect(claude.hooks.PostToolUse).toHaveLength(1);
    expect(cursor.hooks.stop).toHaveLength(1);
    expect(cursor.hooks.afterFileEdit).toHaveLength(1);
  });
});

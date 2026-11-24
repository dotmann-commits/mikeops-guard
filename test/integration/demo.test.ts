import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { promisify } from 'node:util';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const CLI = path.resolve(import.meta.dirname, '../../dist/cli/index.js');
const DEMO = path.resolve(import.meta.dirname, '../../scripts/demo-ai-agent.mjs');

describe.skipIf(!existsSync(CLI))('AI-agent attack demo', () => {
  it('detects the poisoned fixture through real MCP and reaches a clean self-healed rescan', async () => {
    const { stdout, stderr } = await execFileAsync(process.execPath, [DEMO], {
      cwd: path.resolve(import.meta.dirname, '../..'),
      timeout: 15_000,
    });

    expect(stderr).toBe('');
    expect(stdout).toContain('MCP scan: FAILED');
    expect(stdout).toContain('invisible-unicode-control');
    expect(stdout).toContain('mcp-shell-command');
    expect(stdout).toContain('claude-wildcard-bash-hook');
    expect(stdout).toContain('script-injection');
    expect(stdout).toContain('supabase-table-without-rls');
    expect(stdout).toContain('MCP rescan: PASSED (0 findings');
    expect(stdout).toContain('Self-healing loop complete');
  }, 20_000);
});

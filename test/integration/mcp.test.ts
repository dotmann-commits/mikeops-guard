import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { describe, expect, it } from 'vitest';

const CLI = path.resolve(import.meta.dirname, '../../dist/cli/index.js');

describe.skipIf(!existsSync(CLI))('MCP stdio integration', () => {
  it('lists and invokes the read-only repository scan tool through the built CLI', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'guard-mcp-client-'));
    await mkdir(path.join(root, '.github/workflows'), { recursive: true });
    await writeFile(path.join(root, '.github/workflows/ci.yml'), [
      'on: issues',
      'permissions: { contents: read }',
      'jobs:',
      '  unsafe:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "${{ github.event.issue.title }}"',
    ].join('\n'));

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [CLI, 'mcp', root],
      stderr: 'pipe',
    });
    const client = new Client({ name: 'mikeops-guard-test', version: '1.0.0' });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      expect(listed.tools.map((tool) => tool.name)).toContain('mikeops_scan_repository');

      const result = await client.callTool({
        name: 'mikeops_scan_repository',
        arguments: { path: '.', mode: 'fast', fail_on: 'high', max_findings: 10 },
      });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        status: 'failed',
        mode: 'fast',
        totalFindings: 1,
        truncated: false,
      });

      const escaped = await client.callTool({
        name: 'mikeops_scan_repository',
        arguments: { path: '..' },
      });
      expect(escaped.isError).toBe(true);
    } finally {
      await client.close();
    }
  }, 15_000);
});

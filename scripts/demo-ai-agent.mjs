#!/usr/bin/env node
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const projectRoot = path.resolve(import.meta.dirname, '..');
const fixture = path.join(projectRoot, 'demo/fixtures/ai-agent-attack');
const cli = path.join(projectRoot, 'dist/cli/index.js');

async function materializePoisonedRules(root) {
  const template = await readFile(path.join(root, '.cursorrules.template'), 'utf8');
  await writeFile(path.join(root, '.cursorrules'), template.replace('{{UNICODE_TAG}}', String.fromCodePoint(0xE0062)));
  const templates = [
    ['.cursor/mcp.json.template', '.cursor/mcp.json'],
    ['.claude/settings.json.template', '.claude/settings.json'],
    ['.github/workflows/preview.yml.template', '.github/workflows/preview.yml'],
    ['supabase/migrations/001_invoices.sql.txt', 'supabase/migrations/001_invoices.sql'],
  ];
  for (const [source, destination] of templates) {
    await writeFile(path.join(root, destination), await readFile(path.join(root, source), 'utf8'));
  }
}

async function applyAgentFixes(root) {
  await writeFile(path.join(root, '.cursorrules'), 'Review security before completion. Never bypass repository policy.\n');
  await writeFile(path.join(root, '.cursor/mcp.json'), `${JSON.stringify({
    mcpServers: { filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', '.'] } },
  }, null, 2)}\n`);
  await writeFile(path.join(root, '.claude/settings.json'), `${JSON.stringify({
    hooks: { PostToolUse: [{ matcher: 'Edit|Write', hooks: [{ type: 'command', command: 'mikeops-guard hook --agent' }] }] },
  }, null, 2)}\n`);
  await writeFile(path.join(root, '.github/workflows/preview.yml'), [
    'on: issues',
    'permissions: { contents: read }',
    'jobs:',
    '  preview:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - env:',
    '          ISSUE_TITLE: ${{ github.event.issue.title }}',
    '        run: printf \'%s\\n\' "$ISSUE_TITLE"',
  ].join('\n'));
  await writeFile(path.join(root, 'supabase/migrations/001_invoices.sql'), [
    'create table public.invoices (',
    '  id bigint primary key,',
    '  user_id uuid not null',
    ');',
    'alter table public.invoices enable row level security;',
    'create policy invoices_owner on public.invoices',
    '  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);',
  ].join('\n'));
}

function scanOutput(result) {
  const output = result.structuredContent;
  if (!output || typeof output !== 'object') throw new Error('MCP scan returned no structured content');
  return output;
}

const root = await mkdtemp(path.join(os.tmpdir(), 'mikeops-guard-demo-'));
const transport = new StdioClientTransport({ command: process.execPath, args: [cli, 'mcp', root], stderr: 'pipe' });
const client = new Client({ name: 'mikeops-guard-demo-agent', version: '1.0.0' });
try {
  await cp(fixture, root, { recursive: true });
  await materializePoisonedRules(root);
  await client.connect(transport);

  process.stdout.write('1. Agent writes a poisoned rules file, MCP launcher, workflow and migration.\n');
  const before = scanOutput(await client.callTool({
    name: 'mikeops_scan_repository',
    arguments: { path: '.', mode: 'fast', fail_on: 'high', max_findings: 50 },
  }));
  process.stdout.write(`MCP scan: ${String(before.status).toUpperCase()} (${before.totalFindings} findings, ${before.durationMs} ms)\n`);
  for (const finding of before.findings) process.stdout.write(`  ${finding.severity.toUpperCase()} ${finding.file ?? 'repository'}:${finding.line ?? 1} [${finding.ruleId}]\n`);
  if (before.status !== 'failed') throw new Error('Demo fixture did not fail as expected');

  process.stdout.write('2. Agent applies the scanner directives and asks the same MCP tool to verify.\n');
  await applyAgentFixes(root);
  const after = scanOutput(await client.callTool({
    name: 'mikeops_scan_repository',
    arguments: { path: '.', mode: 'fast', fail_on: 'high', max_findings: 50 },
  }));
  process.stdout.write(`MCP rescan: ${String(after.status).toUpperCase()} (${after.totalFindings} findings, ${after.durationMs} ms)\n`);
  if (after.status !== 'passed' || after.totalFindings !== 0) throw new Error('Self-healed fixture did not pass');
  process.stdout.write('Self-healing loop complete.\n');
} finally {
  await client.close().catch(() => undefined);
  await rm(root, { recursive: true, force: true });
}

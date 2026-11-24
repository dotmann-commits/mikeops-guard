import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { configSchema } from '../../src/config/schema.js';
import { discoverFiles } from '../../src/core/discover.js';
import { appSecurityScanner } from '../../src/scanners/app-security/index.js';

async function scanSql(files: Record<string, string>) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'guard-sql-classification-'));
  try {
    for (const [file, source] of Object.entries(files)) {
      const destination = path.join(root, file);
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, source);
    }
    return await appSecurityScanner.run({
      root,
      config: configSchema.parse({}),
      files: await discoverFiles(root, []),
      isGitRepo: false,
      tempDir: root,
      timeoutMs: 1000,
      exec: () => Promise.reject(new Error('not used')),
      skipFile: () => undefined,
      signal: new AbortController().signal,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe('SQL classification and findings', () => {
  it('ignores Supabase markers found only in comments, strings or function bodies outside Supabase paths', async () => {
    const findings = await scanSql({
      'migrations/001.sql': [
        '-- create policy open_write on public.notes for all using (true);',
        '/* alter table public.notes enable row level security; */',
        "select 'a long description of auth.uid and storage.buckets';",
        'do $body$',
        'begin',
        '  perform auth.uid();',
        'end',
        '$body$;',
        'create table public.notes (id int);',
      ].join('\n'),
    });

    expect(findings).toEqual([]);
  });

  it('detects real Supabase statements outside Supabase paths at their original lines', async () => {
    const findings = await scanSql({
      'migrations/001.sql': [
        '-- leading comment',
        'create table public.notes (id int);',
        'create policy open_write on public.notes for all using (true);',
      ].join('\n'),
    });

    expect(findings.map((f) => [f.ruleId, f.file, f.line])).toEqual([
      ['supabase-table-without-rls', 'migrations/001.sql', 2],
      ['supabase-permissive-write-policy', 'migrations/001.sql', 3],
    ]);
  });

  it('keeps path-based SQL detection and RLS checks across migrations', async () => {
    const findings = await scanSql({
      'packages/app/supabase/migrations/001.sql': [
        'create table public.protected (id int);',
        'create table public.exposed (id int);',
      ].join('\n'),
      'migrations/002.sql': 'alter table public.protected enable row level security;',
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'supabase-table-without-rls',
      title: 'Table public.exposed is created without Row Level Security',
      file: 'packages/app/supabase/migrations/001.sql',
      line: 2,
    });
  });
});

import { describe, expect, it } from 'vitest';
import { supabaseSqlFindings } from '../../src/scanners/app-security/sql.js';

describe('SQL finding locations', () => {
  it.each(['\n', '\r\n'])('preserves statement lines with %j line endings', (newline) => {
    const source = [
      '-- leading comment;',
      '',
      '/* multi-line',
      '   comment; */',
      '  create table public.first (id int); create table public.second (id int);',
      '',
      '; -- empty statement;',
      ' \t',
      'create table public.third (',
      '  id int',
      ');',
      '  create policy open_write on public.third for all using (true)',
    ].join(newline);

    const findings = supabaseSqlFindings([{ file: 'migration.sql', source }]);

    expect(findings.map((f) => [f.ruleId, f.line])).toEqual([
      ['supabase-table-without-rls', 5],
      ['supabase-table-without-rls', 5],
      ['supabase-table-without-rls', 9],
      ['supabase-permissive-write-policy', 12],
    ]);
  });

  it('keeps line numbers after masked function bodies and multiline strings', () => {
    const source = [
      'do $body$',
      'begin',
      '  create table public.hidden (id int);',
      'end',
      '$body$;',
      "select 'text",
      "with a newline; ignored';",
      'create table public.visible (id int);',
    ].join('\n');

    const findings = supabaseSqlFindings([{ file: 'migration.sql', source }]);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'supabase-table-without-rls',
      title: 'Table public.visible is created without Row Level Security',
      line: 8,
    });
  });

  it('resets locations for each migration while respecting RLS enabled in a later file', () => {
    const findings = supabaseSqlFindings([
      {
        file: '001_tables.sql',
        source: 'create table public.protected (id int);\n\ncreate table public.exposed (id int);',
      },
      {
        file: '002_rls.sql',
        source: 'create table public.another (id int);\nalter table public.protected enable row level security;',
      },
    ]);

    expect(findings.map((f) => [f.file, f.line, f.title])).toEqual([
      ['001_tables.sql', 3, 'Table public.exposed is created without Row Level Security'],
      ['002_rls.sql', 1, 'Table public.another is created without Row Level Security'],
    ]);
  });

  it('locates a final finding after thousands of unrelated statements', () => {
    const source = 'select 1;\n'.repeat(4000) + 'create table public.exposed (id int)';
    const findings = supabaseSqlFindings([{ file: 'migration.sql', source }]);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'supabase-table-without-rls', line: 4001 });
  });
});

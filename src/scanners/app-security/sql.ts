import type { NewFinding } from '../../core/types.js';

export interface SqlFile {
  file: string;
  source: string;
}

interface Statement {
  file: string;
  line: number;
  text: string;
}

const NAME = String.raw`(?:"?([A-Za-z_][\w$]*)"?\.)?"?([A-Za-z_][\w$]*)"?`;
const CREATE_TABLE = new RegExp(String.raw`^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${NAME}`, 'i');
const ENABLE_RLS = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${NAME}\s+enable\s+row\s+level\s+security`, 'i');
const CREATE_POLICY = new RegExp(String.raw`^create\s+policy\s+("[^"]*"|\S+)\s+on\s+${NAME}([\s\S]*)$`, 'i');
const BUCKET_INSERT = /^insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*\(([\s\S]*?)\)/i;
const BUCKET_UPDATE = /^update\s+storage\.buckets\s+set\s+[\s\S]*\bpublic\s*=\s*true\b/i;
const WRITE_COMMANDS = new Set(['all', 'insert', 'update', 'delete']);

/**
 * Blanks out comments, free-text strings and dollar-quoted bodies (functions, DO blocks) with spaces, keeping newlines,
 * so statements can be matched without commented-out SQL causing findings and line numbers stay correct.
 */
export function maskSql(source: string): string {
  const blank = (text: string): string => text.replace(/[^\n]/g, ' ');
  return source
    .replace(/\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g, blank)
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/--[^\n]*/g, blank)
    .replace(/'(?:[^']|'')*'/g, (m) => (/^'[\w.-]{0,64}'$/.test(m) ? m : `'${blank(m.slice(1, -1))}'`)); // names stay readable
}

function statements(file: SqlFile): Statement[] {
  const masked = maskSql(file.source);
  const out: Statement[] = [];
  let start = 0;
  for (let i = 0; i <= masked.length; i++) {
    if (i === masked.length || masked[i] === ';') {
      const raw = masked.slice(start, i);
      const text = raw.trim().replace(/\s+/g, ' ');
      if (text) {
        const offset = start + raw.length - raw.trimStart().length;
        out.push({ file: file.file, line: masked.slice(0, offset).split('\n').length, text });
      }
      start = i + 1;
    }
  }
  return out;
}

const tableKey = (schema: string | undefined, table: string): string => `${(schema ?? 'public').toLowerCase()}.${table.toLowerCase()}`;

/**
 * Supabase exposes tables in the public schema through its API with the anon key. Without Row Level Security a
 * table is readable and writable by anyone holding that key, which ships in every frontend. Checked across all SQL
 * files together, because RLS is often enabled in a later migration.
 */
export function supabaseSqlFindings(files: readonly SqlFile[]): NewFinding[] {
  const all = files.flatMap(statements);
  const rls = new Set<string>();
  for (const s of all) {
    const m = ENABLE_RLS.exec(s.text);
    if (m) rls.add(tableKey(m[1], m[2] ?? ''));
  }

  const findings: NewFinding[] = [];
  for (const s of all) {
    const created = CREATE_TABLE.exec(s.text);
    if (created && /^create\s+(?:unlogged\s+)?table\b/i.test(s.text) && !/^create\s+temp/i.test(s.text)) {
      const key = tableKey(created[1], created[2] ?? '');
      if (key.startsWith('public.') && !rls.has(key)) {
        findings.push({
          scanner: 'app-security',
          ruleId: 'supabase-table-without-rls',
          title: `Table ${key} is created without Row Level Security`,
          severity: 'high',
          category: 'application',
          file: s.file,
          line: s.line,
          message: `No migration enables Row Level Security on ${key}. Tables in the public schema are reachable through the Supabase API with the anon key, which is shipped to every browser.`,
          remediation: `Add "alter table ${key} enable row level security;" and policies that allow only what each role needs. Verify in the Supabase dashboard (Authentication, Policies).`,
          references: ['https://supabase.com/docs/guides/database/postgres/row-level-security'],
        });
      }
    }

    const policy = CREATE_POLICY.exec(s.text);
    if (policy) {
      const body = policy[4] ?? ''; // groups: 1 policy name, 2 schema, 3 table, 4 the rest of the statement
      const command = (/\bfor\s+(all|insert|update|delete|select)\b/i.exec(body)?.[1] ?? 'all').toLowerCase();
      const allowsEverything = /\b(?:using|with\s+check)\s*\(\s*true\s*\)/i.test(body);
      const onlyServiceRole = /\bto\s+service_role\s*(?:$|using|with)/i.test(body);
      if (WRITE_COMMANDS.has(command) && allowsEverything && !onlyServiceRole) {
        const key = tableKey(policy[2], policy[3] ?? '');
        const insertOnly = command === 'insert';
        findings.push({
          scanner: 'app-security',
          ruleId: 'supabase-permissive-write-policy',
          title: insertOnly
            ? `Anyone allowed by the policy can create rows in ${key}`
            : `Policy lets any permitted role ${command === 'all' ? 'write' : command} every row of ${key}`,
          // Insert-only is the normal pattern for public forms (contact, booking); changing other rows is not.
          severity: insertOnly ? 'low' : 'high',
          category: 'application',
          file: s.file,
          line: s.line,
          message: insertOnly
            ? `Policy ${policy[1] ?? ''} on ${key} allows INSERT with check (true). That suits a public form, but anyone with the anon key can add unlimited rows with any values.`
            : `Policy ${policy[1] ?? ''} on ${key} allows ${command.toUpperCase()} with a condition of "true", so the row owner is never checked: any permitted user can change or remove other people's rows.`,
          remediation: insertOnly
            ? 'If this is a public form, add rate limiting or a CAPTCHA and constrain columns (for example status defaults) in the check. Otherwise restrict it to the owner with auth.uid().'
            : 'Restrict the condition to the owner, for example using (auth.uid() = user_id) and with check (auth.uid() = user_id), and limit the policy to the roles that need it.',
          references: ['https://supabase.com/docs/guides/database/postgres/row-level-security#policies'],
        });
      }
    }

    const insert = BUCKET_INSERT.exec(s.text);
    if (insert) {
      const columns = (insert[1] ?? '').split(',').map((c) => c.trim().replace(/"/g, '').toLowerCase());
      const values = (insert[2] ?? '').split(',').map((v) => v.trim().replace(/^'|'$/g, '').toLowerCase());
      const publicAt = columns.indexOf('public');
      if (publicAt >= 0 && values[publicAt] === 'true') findings.push(publicBucket(s, values[columns.indexOf('id')] ?? values[columns.indexOf('name')]));
    } else if (BUCKET_UPDATE.test(s.text)) {
      findings.push(publicBucket(s, undefined));
    }
  }
  return findings;
}

function publicBucket(s: Statement, bucket: string | undefined): NewFinding {
  return publicBucketFinding(s.file, s.line, bucket);
}

export function publicBucketFinding(file: string, line: number | undefined, bucket: string | undefined): NewFinding {
  return {
    scanner: 'app-security',
    ruleId: 'supabase-public-bucket',
    title: `Storage bucket${bucket ? ` "${bucket}"` : ''} is public`,
    severity: 'medium',
    category: 'application',
    file,
    ...(line ? { line } : {}),
    message: 'Files in a public bucket can be downloaded by anyone who has or guesses the URL, without signing in. That is right for public assets, wrong for user uploads, invoices or documents.',
    remediation: 'Keep the bucket private and serve files with signed URLs, or confirm it only holds files meant for everyone.',
    references: ['https://supabase.com/docs/guides/storage/buckets/fundamentals'],
  };
}

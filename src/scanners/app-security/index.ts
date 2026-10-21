import path from 'node:path';
import { FILE_CONCURRENCY, mapLimit } from '../../core/concurrency.js';
import { readTextFile } from '../../core/files.js';
import type { ScanContext, Scanner } from '../../core/scanner.js';
import type { NewFinding } from '../../core/types.js';
import { envFileFindings, sourceFindings, type ProjectKind } from './frontend.js';
import { maskSql, publicBucketFinding, supabaseSqlFindings } from './sql.js';

/** Generated bundles and very large files are not hand-written source; reading them would only slow the scan. */
const MAX_SOURCE_BYTES = 512 * 1024;
/** package.json only decides which framework rules apply. A huge one is not a real manifest. */
const MAX_MANIFEST_BYTES = 256 * 1024;
/** Frameworks where only files marked "use client" run in the browser. */
const CLIENT_DIRECTIVE_FRAMEWORKS = ['next'];
/** Evidence that a package is a web app whose code reaches the browser. */
const BROWSER_PACKAGES = [
  'vite', 'react-scripts', 'react', 'react-dom', 'vue', 'svelte', '@angular/core', 'next', 'expo', 'react-native',
  '@tanstack/react-start', '@remix-run/react', '@sveltejs/kit', 'nuxt', 'astro', 'solid-js', 'preact', 'webpack', 'parcel',
];
/** Compiled output: bundles are not hand-written source, and they would duplicate findings from the real files. */
const BUILD_OUTPUT = new Set(['dist', 'build', '.next', 'out', 'coverage', '.output', '.vercel', '.netlify']);
/** SQL is treated as Supabase only with evidence: a supabase/ path, or Postgres features Supabase relies on. */
const SUPABASE_SQL = /\bauth\.(?:uid|users|jwt|role)\b|\bstorage\.(?:buckets|objects)\b|row\s+level\s+security|\bcreate\s+policy\b/i;

function isSupabaseSql(file: string, source: string): boolean {
  return file.split('/').includes('supabase') || SUPABASE_SQL.test(maskSql(source)); // statements, not comments
}

function isBuildOutput(file: string): boolean {
  return file.split('/').slice(0, -1).some((segment) => BUILD_OUTPUT.has(segment));
}


interface SourceFile {
  file: string;
  source: string;
}

async function readAll(ctx: ScanContext, list: readonly string[], maxBytes: number, affectsCoverage: boolean): Promise<(SourceFile | null)[]> {
  return mapLimit(list, FILE_CONCURRENCY, async (file) => {
    const read = await readTextFile(path.join(ctx.root, file), maxBytes);
    if (read.ok) return { file, source: read.text };
    ctx.skipFile({ file, reason: read.reason, affectsCoverage });
    return null;
  });
}

/** The nearest package.json decides which framework rules apply to a file (monorepos included). */
function projectKindFinder(root: string): (file: string) => Promise<ProjectKind> {
  const cache = new Map<string, Promise<ProjectKind>>();
  const load = async (dir: string): Promise<ProjectKind> => {
    try {
      const manifest = await readTextFile(path.join(root, dir, 'package.json'), MAX_MANIFEST_BYTES);
      if (!manifest.ok) throw new Error(manifest.reason);
      const pkg = JSON.parse(manifest.text) as Record<string, unknown>;
      const deps = { ...(pkg.dependencies as object | undefined), ...(pkg.devDependencies as object | undefined) };
      return {
        browser: BROWSER_PACKAGES.some((name) => name in deps),
        clientDirective: CLIENT_DIRECTIVE_FRAMEWORKS.some((name) => name in deps),
      };
    } catch {
      if (dir === '' || dir === '.') return { browser: false, clientDirective: false };
      return find(path.posix.dirname(dir));
    }
  };
  const find = (dir: string): Promise<ProjectKind> => {
    const key = dir === '.' ? '' : dir;
    let pending = cache.get(key);
    if (!pending) {
      pending = load(key);
      cache.set(key, pending);
    }
    return pending;
  };
  return (file) => find(path.posix.dirname(file));
}

const BUCKET_TABLE = /^\[storage\.buckets\.([A-Za-z0-9_-]+)\]\s*$/;

/** supabase/config.toml (Supabase CLI): [storage.buckets.<name>] sections with public = true. */
export function supabaseConfigFindings(file: string, source: string): NewFinding[] {
  const findings: NewFinding[] = [];
  let bucket: string | undefined;
  source.split('\n').forEach((text, i) => {
    if (text.trim().startsWith('[')) bucket = BUCKET_TABLE.exec(text.trim())?.[1];
    else if (bucket && /^\s*public\s*=\s*true\b/.test(text)) findings.push(publicBucketFinding(file, i + 1, bucket));
  });
  return findings;
}

export const appSecurityScanner: Scanner = {
  id: 'app-security',
  title: 'App security (env, Supabase, frontend)',
  category: 'application',
  tool: () => null,
  skipReason: (ctx) => {
    const f = ctx.files;
    return f.envFiles.length + f.sqlFiles.length + f.sourceFiles.length + f.supabaseConfigs.length === 0
      ? 'no environment files, SQL or JavaScript/TypeScript source found'
      : null;
  },
  async run(ctx) {
    const { root, files } = ctx;
    const kindOf = projectKindFinder(root);
    const present = <T>(items: (T | null)[]): T[] => items.filter((x): x is T => x !== null);

    // Reads run one group at a time, each bounded, so a large monorepo never has thousands of files open at once.
    const env = await readAll(ctx, files.envFiles, MAX_SOURCE_BYTES, true);
    const sql = await readAll(ctx, files.sqlFiles, MAX_SOURCE_BYTES, true);
    // Oversized JavaScript is almost always a vendored or generated bundle, so it is listed but does not mark the scan incomplete.
    const source = await readAll(ctx, files.sourceFiles.filter((f) => !isBuildOutput(f)), MAX_SOURCE_BYTES, false);
    const configs = await readAll(ctx, files.supabaseConfigs, MAX_SOURCE_BYTES, true);
    const sourceResults = await mapLimit(present(source), FILE_CONCURRENCY, async (f) => sourceFindings(f.file, f.source, await kindOf(f.file)));
    return [
      ...present(env).flatMap((f) => envFileFindings(f.file, f.source)),
      ...supabaseSqlFindings(present(sql).filter((f) => isSupabaseSql(f.file, f.source))),
      ...sourceResults.flat(),
      ...present(configs).flatMap((f) => supabaseConfigFindings(f.file, f.source)),
    ];
  },
};

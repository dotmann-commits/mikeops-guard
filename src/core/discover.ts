import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { createMatcher, toPosix } from './glob.js';

export interface DiscoveredFiles {
  dockerfiles: string[];
  workflows: string[];
  /** .env, .env.local, .env.production and similar (examples and templates included: their variable names matter). */
  envFiles: string[];
  sqlFiles: string[];
  /** JavaScript and TypeScript source, including Vue, Svelte and Astro components. */
  sourceFiles: string[];
  /** supabase/config.toml files. */
  supabaseConfigs: string[];
  fileCount: number;
}

const ALWAYS_SKIPPED_DIRS = new Set(['.git', 'node_modules']);
const DOCKERFILE_NAME = /^(?:dockerfile|containerfile)(?:\..+)?$|\.(?:dockerfile|containerfile)$/i;
const WORKFLOW_PATH = /^\.github\/workflows\/[^/]+\.ya?ml$/;

export function isDockerfile(relativePath: string): boolean {
  return DOCKERFILE_NAME.test(path.posix.basename(relativePath));
}

export function isWorkflow(relativePath: string): boolean {
  return WORKFLOW_PATH.test(relativePath);
}

const ENV_FILE = /^\.env(?:\.[A-Za-z0-9_-]+)*$/;
const SOURCE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;

export function isEnvFile(relativePath: string): boolean {
  return ENV_FILE.test(path.posix.basename(relativePath));
}

/** Walks the target read-only. Symlinks are not followed so a scan never leaves the root. */
export async function discoverFiles(root: string, exclude: readonly string[]): Promise<DiscoveredFiles> {
  const excluded = createMatcher(exclude);
  const result: DiscoveredFiles = { dockerfiles: [], workflows: [], envFiles: [], sqlFiles: [], sourceFiles: [], supabaseConfigs: [], fileCount: 0 };
  const pending = [''];

  while (pending.length > 0) {
    const relDir = pending.pop() ?? '';
    const entries = await readdir(path.join(root, relDir), { withFileTypes: true });
    for (const entry of entries) {
      const rel = toPosix(path.posix.join(relDir, entry.name));
      if (entry.isDirectory()) {
        if (ALWAYS_SKIPPED_DIRS.has(entry.name) || excluded(`${rel}/`)) continue;
        pending.push(rel);
      } else if (entry.isFile() && !excluded(rel)) {
        result.fileCount++;
        if (isDockerfile(rel)) result.dockerfiles.push(rel);
        if (isWorkflow(rel)) result.workflows.push(rel);
        if (isEnvFile(rel)) result.envFiles.push(rel);
        if (rel.endsWith('.sql')) result.sqlFiles.push(rel);
        if (SOURCE_FILE.test(rel) && !rel.endsWith('.d.ts')) result.sourceFiles.push(rel);
        if (rel === 'supabase/config.toml' || rel.endsWith('/supabase/config.toml')) result.supabaseConfigs.push(rel);
      }
    }
  }

  for (const list of [result.dockerfiles, result.workflows, result.envFiles, result.sqlFiles, result.sourceFiles, result.supabaseConfigs]) list.sort();
  return result;
}

export async function isGitRepository(root: string): Promise<boolean> {
  try {
    await stat(path.join(root, '.git'));
    return true;
  } catch {
    return false;
  }
}

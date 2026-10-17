import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { createMatcher, toPosix } from './glob.js';

export interface DiscoveredFiles {
  dockerfiles: string[];
  workflows: string[];
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

/** Walks the target read-only. Symlinks are not followed so a scan never leaves the root. */
export async function discoverFiles(root: string, exclude: readonly string[]): Promise<DiscoveredFiles> {
  const excluded = createMatcher(exclude);
  const result: DiscoveredFiles = { dockerfiles: [], workflows: [], fileCount: 0 };
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
      }
    }
  }

  result.dockerfiles.sort();
  result.workflows.sort();
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

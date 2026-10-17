import { accessSync, constants, statSync } from 'node:fs';
import path from 'node:path';

export type ToolName = 'hadolint' | 'trivy' | 'actionlint' | 'gitleaks' | 'osv-scanner';

export interface ToolInfo {
  name: ToolName;
  versionArgs: readonly string[];
  brew: string;
  docs: string;
}

export const TOOLS: Record<ToolName, ToolInfo> = {
  hadolint: {
    name: 'hadolint',
    versionArgs: ['--version'],
    brew: 'brew install hadolint',
    docs: 'https://github.com/hadolint/hadolint#install',
  },
  trivy: {
    name: 'trivy',
    versionArgs: ['--version'],
    brew: 'brew install trivy',
    docs: 'https://trivy.dev/latest/getting-started/installation/',
  },
  actionlint: {
    name: 'actionlint',
    versionArgs: ['-version'],
    brew: 'brew install actionlint',
    docs: 'https://github.com/rhysd/actionlint/blob/main/docs/install.md',
  },
  gitleaks: {
    name: 'gitleaks',
    versionArgs: ['version'],
    brew: 'brew install gitleaks',
    docs: 'https://github.com/gitleaks/gitleaks#installing',
  },
  'osv-scanner': {
    name: 'osv-scanner',
    versionArgs: ['--version'],
    brew: 'brew install osv-scanner',
    docs: 'https://google.github.io/osv-scanner/installation/',
  },
};

export function installHint(tool: ToolName): string {
  const info = TOOLS[tool];
  return `Install with "${info.brew}" or see ${info.docs}`;
}

export type BinaryResolver = (name: string) => string | null;

/** Looks a binary up on PATH the same way a shell would, without spawning one. */
export function resolveBinary(
  name: string,
  envPath = process.env.PATH ?? '',
  platform: NodeJS.Platform = process.platform,
): string | null {
  const extensions = platform === 'win32' ? ['.exe', '.cmd', ''] : [''];
  for (const dir of envPath.split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of extensions) {
      const candidate = path.join(dir, name + ext);
      if (isExecutableFile(candidate)) return candidate;
    }
  }
  return null;
}

function isExecutableFile(file: string): boolean {
  try {
    if (!statSync(file).isFile()) return false;
    accessSync(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

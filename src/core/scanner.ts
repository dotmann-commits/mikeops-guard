import type { GuardConfig } from '../config/schema.js';
import type { DiscoveredFiles } from './discover.js';
import type { ExecFn } from './exec.js';
import type { ToolName } from './tools.js';
import type { Category, NewFinding, ScannerId } from './types.js';

export interface ScanContext {
  /** Absolute path of the directory being scanned. */
  root: string;
  files: DiscoveredFiles;
  config: GuardConfig;
  isGitRepo: boolean;
  /** Private scratch directory outside the target, removed after the scan. */
  tempDir: string;
  timeoutMs: number;
  exec: ExecFn;
  /** Absolute path of the external binary, when the scanner needs one. */
  binary?: string;
}

export interface Scanner {
  id: ScannerId;
  title: string;
  category: Category;
  /** External binary this scanner shells out to, or null for built-in checks. */
  tool(config: GuardConfig): ToolName | null;
  /** Returns a reason to skip (for example "no Dockerfiles found"), or null to run. */
  skipReason(ctx: ScanContext): string | null;
  run(ctx: ScanContext): Promise<NewFinding[]>;
}

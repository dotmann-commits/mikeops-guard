import { describe, expect, it } from 'vitest';
import { configSchema } from '../../src/config/schema.js';
import type { ExecFn } from '../../src/core/exec.js';
import type { ScanContext } from '../../src/core/scanner.js';
import { dependenciesScanner } from '../../src/scanners/dependencies.js';
import { trivyConfigScanner } from '../../src/scanners/trivy-config.js';

function context(exec: ExecFn, config = configSchema.parse({ exclude: ['vendor/**'] })): ScanContext {
  return { root: '/repo', config, files: { dockerfiles: [], workflows: [], envFiles: [], sqlFiles: [], sourceFiles: [], supabaseConfigs: [], fileCount: 0 }, isGitRepo: true, tempDir: '/tmp/x', timeoutMs: 1000, exec, binary: '/usr/bin/trivy', skipFile: () => undefined, signal: new AbortController().signal };
}

describe('trivy arguments', () => {
  it('config scans skip node_modules and .git, plus the user excludes', async () => {
    let args: readonly string[] = [];
    const exec: ExecFn = (_cmd, a) => ((args = a), Promise.resolve({ code: 0, stdout: '{"Results":[]}', stderr: '' }));
    await trivyConfigScanner.run(context(exec));
    const skipped = args.flatMap((a, i) => (args[i - 1] === '--skip-dirs' ? [a] : []));
    expect(skipped).toEqual(['**/node_modules', '**/.git', 'vendor']);
  });

  it('dependency scans with trivy do not skip node_modules', async () => {
    let args: readonly string[] = [];
    const exec: ExecFn = (_cmd, a) => ((args = a), Promise.resolve({ code: 0, stdout: '{"Results":[]}', stderr: '' }));
    await dependenciesScanner.run(context(exec, configSchema.parse({ scanners: { dependencies: { engine: 'trivy' } } })));
    expect(args).not.toContain('**/node_modules');
  });
});

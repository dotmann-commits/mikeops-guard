import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { CliIo } from '../../src/cli/io.js';
import { main } from '../../src/cli/main.js';
import type { Report } from '../../src/core/types.js';

const FIXTURE = path.resolve(import.meta.dirname, '../fixtures/sample-repo');
const OVER_ONE_MB = 1024 * 1024 + 1;
const OVER_HALF_MB = 512 * 1024 + 1;

async function scan(repo: string, only: string): Promise<Report> {
  let out = '';
  const io: CliIo = { cwd: repo, env: { PATH: '' }, isTty: false, stdout: (t) => void (out += t), stderr: () => undefined };
  await main(['scan', repo, '--only', only, '--json', '-', '--fail-on', 'none'], io, { resolveBinary: () => null });
  return JSON.parse(out) as Report;
}

describe('oversized files in the scanned repository', () => {
  let repo: string;

  beforeAll(async () => {
    repo = await mkdtemp(path.join(os.tmpdir(), 'guard-oversized-'));
    await cp(FIXTURE, repo, { recursive: true });
    // A YAML comment keeps it a valid workflow: only its size is the problem.
    await writeFile(path.join(repo, '.github/workflows/huge.yml'), `# ${'x'.repeat(OVER_ONE_MB)}\non: push\njobs: {}\n`);
    await mkdir(path.join(repo, 'supabase/migrations'), { recursive: true });
    await writeFile(path.join(repo, 'supabase/migrations/001_big.sql'), `-- ${'x'.repeat(OVER_HALF_MB)}\n`);
    await mkdir(path.join(repo, 'web/src'), { recursive: true });
    await writeFile(path.join(repo, 'web/package.json'), '{"dependencies":{"vite":"5.0.0"}}');
    await writeFile(path.join(repo, 'web/src/vendor.js'), `// ${'x'.repeat(OVER_HALF_MB)}\n`);
  });

  afterAll(async () => {
    await rm(repo, { recursive: true, force: true });
  });

  it('marks the workflow audit incomplete and names the file, while still checking the others', async () => {
    const report = await scan(repo, 'workflow-audit');
    const outcome = report.scanners.find((s) => s.scanner === 'workflow-audit');
    expect(outcome).toMatchObject({ status: 'ok', incomplete: true, skippedFileCount: 1 });
    expect(outcome?.skippedFiles).toEqual([{ file: '.github/workflows/huge.yml', reason: 'larger than 1 MB' }]);
    expect(outcome?.reason).toContain('.github/workflows/huge.yml');
    expect(report.findings.some((f) => f.file === '.github/workflows/pr-preview.yml')).toBe(true);
    expect(report.status).toBe('incomplete');
  });

  it('treats an oversized SQL migration as a coverage gap but a large JS bundle as a note only', async () => {
    const report = await scan(repo, 'app-security');
    const outcome = report.scanners.find((s) => s.scanner === 'app-security');
    expect(outcome?.incomplete).toBe(true);
    expect(outcome?.skippedFiles?.map((s) => s.file).sort()).toEqual(['supabase/migrations/001_big.sql', 'web/src/vendor.js']);

    await rm(path.join(repo, 'supabase/migrations/001_big.sql'));
    const withoutSql = await scan(repo, 'app-security');
    const jsOnly = withoutSql.scanners.find((s) => s.scanner === 'app-security');
    expect(jsOnly).toMatchObject({ incomplete: false, skippedFileCount: 1 });
  });
});

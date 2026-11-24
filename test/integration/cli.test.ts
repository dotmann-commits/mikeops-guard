import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { cp, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { CliIo } from '../../src/cli/io.js';
import { main } from '../../src/cli/main.js';
import type { Report } from '../../src/core/types.js';

const FIXTURE = path.resolve(import.meta.dirname, '../fixtures/sample-repo');
const noTools = () => null;
const execFileAsync = promisify(execFile);

interface Captured {
  io: CliIo;
  out: () => string;
  err: () => string;
}

function capture(cwd: string): Captured {
  let out = '';
  let err = '';
  return {
    io: { cwd, env: { PATH: '' }, isTty: false, stdout: (t) => void (out += t), stderr: (t) => void (err += t) },
    out: () => out,
    err: () => err,
  };
}

async function snapshot(dir: string): Promise<Record<string, string>> {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  const files = entries.filter((e) => e.isFile()).map((e) => path.join(e.parentPath, e.name));
  const hashes = await Promise.all(
    files.map(async (f): Promise<[string, string]> => [path.relative(dir, f), createHash('sha256').update(await readFile(f)).digest('hex')]),
  );
  return Object.fromEntries(hashes.sort(([a], [b]) => a.localeCompare(b)));
}

describe('mikeops-guard scan (end to end)', () => {
  let repo: string;
  let outDir: string;

  beforeAll(async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), 'guard-e2e-'));
    repo = path.join(base, 'repo');
    outDir = path.join(base, 'out');
    await cp(FIXTURE, repo, { recursive: true });
  });

  afterAll(async () => {
    await rm(path.dirname(repo), { recursive: true, force: true });
  });

  it('finds the planted workflow issues, fails the policy and never touches the target', async () => {
    const before = await snapshot(repo);
    const run = capture(outDir);
    const code = await main(['scan', repo, '--json', 'report.json', '--html', 'report.html', '--sarif', 'report.sarif', '--markdown', 'summary.md'], run.io, { resolveBinary: noTools });

    expect(code).toBe(1);
    expect(await snapshot(repo)).toEqual(before);

    const report = JSON.parse(await readFile(path.join(outDir, 'report.json'), 'utf8')) as Report;
    const rules = report.findings.map((f) => `${f.ruleId}@${f.file}:${f.line ?? ''}`);
    expect(rules).toEqual(
      expect.arrayContaining([
        'pull-request-target-checkout@.github/workflows/pr-preview.yml:10',
        'script-injection@.github/workflows/pr-preview.yml:16',
        'write-all-permissions@.github/workflows/pr-preview.yml:5',
        'unpinned-action@.github/workflows/pr-preview.yml:17',
      ]),
    );
    expect(report.findings.some((f) => f.file === '.github/workflows/ci.yml')).toBe(false);

    const missingTools = report.scanners.filter((s) => s.status === 'skipped' && s.incomplete);
    expect(missingTools.map((s) => s.scanner)).toEqual(['gitleaks', 'actionlint', 'hadolint', 'trivy-config', 'dependencies']);
    expect(missingTools.every((s) => s.installHint?.includes('brew install'))).toBe(true);
    // Nothing for app-security to check in this fixture: a not-applicable skip, not a coverage gap.
    expect(report.scanners.find((s) => s.scanner === 'app-security')).toMatchObject({ status: 'skipped', incomplete: false });

    expect(await readFile(path.join(outDir, 'report.html'), 'utf8')).toContain('pull_request_target checks out untrusted PR code');
    expect(JSON.parse(await readFile(path.join(outDir, 'report.sarif'), 'utf8'))).toMatchObject({ version: '2.1.0' });
    expect(await readFile(path.join(outDir, 'summary.md'), 'utf8')).toContain('# MikeOps Guard — Failed');
    expect(run.out()).toContain('FAILED');
  });

  it('is incomplete, never a clean pass, when scanners could not run', async () => {
    const run = capture(outDir);
    const code = await main(['scan', repo, '--fail-on', 'none', '--quiet'], run.io, { resolveBinary: noTools });
    expect(code).toBe(0); // optional tools missing: the exit code is unchanged, the verdict is not "PASSED"
    expect(run.out()).toContain('INCOMPLETE');
    expect(run.out()).not.toContain('PASSED');
  });

  it('passes only when every selected scanner that applies actually ran', async () => {
    const run = capture(outDir);
    await main(['scan', repo, '--fail-on', 'none', '--json', '-', '--only', 'workflow-audit'], run.io, { resolveBinary: noTools });
    const report = JSON.parse(run.out()) as Report;
    expect(report.status).toBe('incomplete'); // the other five were not selected, and the report says so
    const ran = report.scanners.filter((s) => !s.incomplete);
    expect(ran.map((s) => s.scanner)).toEqual(['workflow-audit']);
  });

  it('writes clean JSON to stdout with --json -', async () => {
    const run = capture(outDir);
    await main(['scan', repo, '--json', '-', '--only', 'workflow-audit'], run.io, { resolveBinary: noTools });
    const report = JSON.parse(run.out()) as Report;
    expect(report.scanners.filter((s) => s.status !== 'skipped' || !s.incomplete).map((s) => s.scanner)).toEqual(['workflow-audit']);
    expect(report.scanners.find((s) => s.scanner === 'gitleaks')?.reason).toBe('disabled by the config or by --only/--skip');
    expect(run.err()).toContain('Summary');
  });

  it('uses a prior JSON report as a baseline and records suppressed findings', async () => {
    const baseline = path.join(outDir, 'adoption-baseline.json');
    const captureRun = capture(outDir);
    await main(['scan', repo, '--only', 'workflow-audit', '--fail-on', 'none', '--json', baseline], captureRun.io, { resolveBinary: noTools });

    const scopedRun = capture(outDir);
    const code = await main(['scan', repo, '--only', 'workflow-audit', '--baseline', baseline, '--json', '-'], scopedRun.io, { resolveBinary: noTools });
    const report = JSON.parse(scopedRun.out()) as Report;
    expect(code).toBe(0);
    expect(report.findings).toEqual([]);
    expect(report.scope).toMatchObject({ baselineSuppressed: 5, unchangedSuppressed: 0 });
    expect(report.status).toBe('incomplete');
  });

  it('rejects a missing baseline instead of silently passing', async () => {
    const run = capture(outDir);
    expect(await main(['scan', repo, '--only', 'workflow-audit', '--baseline', path.join(outDir, 'missing.json')], run.io, { resolveBinary: noTools })).toBe(2);
    expect(run.err()).toContain('Baseline file does not exist');
  });

  it('limits the verdict to tracked changes and untracked files since a real Git ref', async () => {
    const changedRepo = await mkdtemp(path.join(os.tmpdir(), 'guard-diff-'));
    const workflowDir = path.join(changedRepo, '.github/workflows');
    const vulnerable = 'name: Risky\non: push\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n';
    try {
      await mkdir(workflowDir, { recursive: true });
      await writeFile(path.join(workflowDir, 'legacy.yml'), vulnerable);
      await execFileAsync('git', ['init'], { cwd: changedRepo });
      await execFileAsync('git', ['add', '.'], { cwd: changedRepo });
      await execFileAsync('git', ['-c', 'user.name=MikeOps Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture'], { cwd: changedRepo });

      const cleanRun = capture(outDir);
      await main(['scan', changedRepo, '--only', 'workflow-audit', '--changed-since', 'HEAD', '--json', '-'], cleanRun.io, { resolveBinary: noTools });
      expect((JSON.parse(cleanRun.out()) as Report).findings).toEqual([]);

      await writeFile(path.join(workflowDir, 'new.yml'), vulnerable);
      const changedRun = capture(outDir);
      await main(['scan', changedRepo, '--only', 'workflow-audit', '--changed-since', 'HEAD', '--json', '-'], changedRun.io, { resolveBinary: noTools });
      const report = JSON.parse(changedRun.out()) as Report;
      expect(report.findings.length).toBeGreaterThan(0);
      expect(report.findings.every((finding) => finding.file === '.github/workflows/new.yml')).toBe(true);
      expect(report.scope).toMatchObject({ changedSince: 'HEAD', changedFiles: 1 });
    } finally {
      await rm(changedRepo, { recursive: true, force: true });
    }
  });

  it('fails with exit 3 when --require-tools is set and a scanner is missing', async () => {
    const run = capture(outDir);
    const code = await main(['scan', repo, '--only', 'hadolint', '--require-tools'], run.io, { resolveBinary: noTools });
    expect(code).toBe(3);
  });

  it('exits 2 with a clear message for a missing target', async () => {
    const run = capture(outDir);
    expect(await main(['scan', path.join(repo, 'nope')], run.io)).toBe(2);
    expect(run.err()).toContain('Target path does not exist');
  });
});

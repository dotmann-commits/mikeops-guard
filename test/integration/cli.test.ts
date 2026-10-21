import { createHash } from 'node:crypto';
import { cp, mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { CliIo } from '../../src/cli/io.js';
import { main } from '../../src/cli/main.js';
import type { Report } from '../../src/core/types.js';

const FIXTURE = path.resolve(import.meta.dirname, '../fixtures/sample-repo');
const noTools = () => null;

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
    const code = await main(['scan', repo, '--json', 'report.json', '--html', 'report.html'], run.io, { resolveBinary: noTools });

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

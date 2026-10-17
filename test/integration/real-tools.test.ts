import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { main } from '../../src/cli/main.js';
import { resolveBinary } from '../../src/core/tools.js';
import type { Report } from '../../src/core/types.js';

/**
 * Runs the real scanners when they are installed, and skips otherwise.
 * CI installs them with scripts/install-scanners.sh, so these run there.
 */
const FIXTURE = path.resolve(import.meta.dirname, '../fixtures/sample-repo');
const has = (tool: string) => resolveBinary(tool) !== null;
// Real scanners download databases and hit the network, so they need far more than the 5s default.
const REAL_TOOL_TIMEOUT_MS = 180_000;
const ALPHANUMERIC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** A random GitHub token-shaped string, generated per run so no real-looking secret lives in this repo. */
function fakeToken(): string {
  const bytes = randomBytes(36);
  return `ghp_${[...bytes].map((b) => ALPHANUMERIC[b % ALPHANUMERIC.length]).join('')}`;
}

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', ['-c', 'user.name=Guard Test', '-c', 'user.email=guard@example.invalid', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    stdio: 'ignore',
  });
}

async function scan(repo: string, scanner: string): Promise<Report> {
  let out = '';
  const io = { cwd: repo, env: process.env, isTty: false, stdout: (t: string) => void (out += t), stderr: () => undefined };
  await main(['scan', repo, '--only', scanner, '--json', '-', '--fail-on', 'none'], io);
  return JSON.parse(out) as Report;
}

describe('real scanner integrations', { timeout: REAL_TOOL_TIMEOUT_MS }, () => {
  let repo: string;

  beforeAll(async () => {
    repo = await mkdtemp(path.join(os.tmpdir(), 'guard-real-'));
    await cp(FIXTURE, repo, { recursive: true });
    git(repo, 'init', '-q');
    await writeFile(path.join(repo, 'deploy.sh'), `export GITHUB_TOKEN=${fakeToken()}\n`);
    git(repo, 'add', '.');
    git(repo, 'commit', '-qm', 'add deploy script');
    // Remove the secret again: it must still be found in history.
    await writeFile(path.join(repo, 'deploy.sh'), 'export GITHUB_TOKEN="$TOKEN"\n');
    git(repo, 'commit', '-qam', 'use env var');
  });

  afterAll(async () => {
    await rm(repo, { recursive: true, force: true });
  });

  it.skipIf(!has('gitleaks'))('gitleaks finds a secret that only exists in git history, redacted', async () => {
    const report = await scan(repo, 'gitleaks');
    expect(report.scanners[0]?.status).toBe('ok');
    const leak = report.findings.find((f) => f.file === 'deploy.sh');
    expect(leak).toMatchObject({ severity: 'critical', category: 'secret', line: 1 });
    expect(leak?.message).toContain('git history');
    expect(JSON.stringify(report)).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
  });

  it.skipIf(!has('hadolint'))('hadolint reports Dockerfile issues with lines', async () => {
    const report = await scan(repo, 'hadolint');
    const rules = report.findings.map((f) => `${f.ruleId}:${f.line ?? ''}`);
    expect(rules).toEqual(expect.arrayContaining(['DL3007:1', 'DL3020:3']));
    expect(report.findings.every((f) => f.file === 'docker/app.Dockerfile')).toBe(true);
  });

  it.skipIf(!has('actionlint'))('actionlint flags untrusted input in the PR workflow', async () => {
    const report = await scan(repo, 'actionlint');
    expect(report.scanners[0]?.status).toBe('ok');
    const expression = report.findings.find((f) => f.ruleId === 'actionlint-expression');
    // actionlint reports the line of the run: key. The built-in audit points at the exact line inside it.
    expect(expression).toMatchObject({ file: '.github/workflows/pr-preview.yml', line: 14 });
  });

  it.skipIf(!has('trivy'))('trivy config reports Dockerfile misconfigurations', async () => {
    const report = await scan(repo, 'trivy-config');
    expect(report.scanners[0]?.status).toBe('ok');
    expect(report.findings.some((f) => f.file === 'docker/app.Dockerfile')).toBe(true);
  });

  it.skipIf(!has('osv-scanner'))('osv-scanner finds a known vulnerable dependency', async () => {
    const lockfile = path.join(repo, 'requirements.txt');
    await writeFile(lockfile, 'jinja2==2.4.1\n');
    try {
      const report = await scan(repo, 'dependencies');
      expect(report.scanners[0]?.status).toBe('ok');
      expect(report.findings.some((f) => f.file === 'requirements.txt' && f.title.startsWith('jinja2@2.4.1'))).toBe(true);
    } finally {
      await rm(lockfile, { force: true });
    }
  });

  it('leaves the scanned repository untouched', async () => {
    const status = execFileSync('git', ['status', '--porcelain'], { cwd: repo, encoding: 'utf8' });
    expect(status).toBe('');
    expect(await readFile(path.join(repo, 'deploy.sh'), 'utf8')).not.toContain('ghp_');
  });
});

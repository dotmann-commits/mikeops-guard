#!/usr/bin/env node
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import process from 'node:process';
import { configSchema } from '../dist/config/schema.js';
import { runScan } from '../dist/core/run.js';
import { sourceFindings } from '../dist/scanners/app-security/frontend.js';
import { appSecurityScanner } from '../dist/scanners/app-security/index.js';
import { workflowAuditScanner } from '../dist/scanners/workflow-audit/index.js';
import { findUntrustedExpressions } from '../dist/scanners/workflow-audit/rules/untrusted-contexts.js';

const FRONTEND_REFERENCES = 8_000;
const WORKFLOW_EXPRESSIONS = 8_000;
const E2E_FINDINGS_PER_SCANNER = 2_000;
const WARMUP_RUNS = 2;
const MEASURED_RUNS = 7;
const browserProject = { browser: true, clientDirective: false };

function digest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

async function measure(name, inputSize, expectedFindings, operation) {
  let expectedDigest;
  for (let i = 0; i < WARMUP_RUNS; i++) {
    const output = await operation();
    expectedDigest ??= digest(output);
    if (digest(output) !== expectedDigest) throw new Error(`${name} output changed during warmup`);
  }

  const durations = [];
  for (let i = 0; i < MEASURED_RUNS; i++) {
    const started = performance.now();
    const output = await operation();
    durations.push(performance.now() - started);
    if (output.length !== expectedFindings) {
      throw new Error(`${name} returned ${output.length} findings; expected ${expectedFindings}`);
    }
    if (digest(output) !== expectedDigest) throw new Error(`${name} output changed between runs`);
  }

  durations.sort((a, b) => a - b);
  return {
    name,
    inputSize,
    findings: expectedFindings,
    medianMs: Number(percentile(durations, 0.5).toFixed(1)),
    p95Ms: Number(percentile(durations, 0.95).toFixed(1)),
  };
}

function formatTable(results) {
  const rows = [
    '| Benchmark | Input bytes | Findings | Median | p95 |',
    '|---|---:|---:|---:|---:|',
    ...results.map((result) =>
      `| ${result.name} | ${result.inputSize.toLocaleString('en-US')} | ${result.findings.toLocaleString('en-US')} | ${result.medianMs.toFixed(1)} ms | ${result.p95Ms.toFixed(1)} ms |`,
    ),
  ];
  return rows.join('\n');
}

async function createEndToEndFixture(root) {
  const workflowLines = Array.from(
    { length: E2E_FINDINGS_PER_SCANNER },
    (_, index) => `          echo "${index} \${{ github.event.issue.title }}"`,
  ).join('\n');
  const frontendLines = 'process.env.VITE_SECRET;\n'.repeat(E2E_FINDINGS_PER_SCANNER);
  const sqlLines = '-- create policy in a comment; auth.uid\n'.repeat(E2E_FINDINGS_PER_SCANNER) + [
    'create table public.exposed (id int);',
    'create policy open_write on public.exposed for all using (true);',
  ].join('\n');

  await mkdir(path.join(root, '.github/workflows'), { recursive: true });
  await mkdir(path.join(root, 'src'), { recursive: true });
  await mkdir(path.join(root, 'migrations'), { recursive: true });
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ dependencies: { vite: '1.0.0' } }));
  await writeFile(path.join(root, 'src/client.ts'), frontendLines);
  await writeFile(path.join(root, 'migrations/001.sql'), sqlLines);
  const workflowSource = [
    'on: issues',
    'permissions: { contents: read }',
    'jobs:',
    '  audit:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: |',
    workflowLines,
  ].join('\n');
  await writeFile(
    path.join(root, '.github/workflows/ci.yml'),
    workflowSource,
  );
  return Buffer.byteLength(frontendLines) + Buffer.byteLength(sqlLines) + Buffer.byteLength(workflowSource);
}

async function benchmark() {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), 'mikeops-guard-benchmark-'));
  try {
    const endToEndBytes = await createEndToEndFixture(tempRoot);
    const frontendSource = 'process.env.VITE_SECRET;\n'.repeat(FRONTEND_REFERENCES);
    const workflowSource = '${{ github.head_ref }}\n'.repeat(WORKFLOW_EXPRESSIONS);
    const config = configSchema.parse({});
    const scanOptions = {
      root: tempRoot,
      config,
      scanners: [workflowAuditScanner, appSecurityScanner],
      toolVersion: 'benchmark',
      resolveBinary: () => null,
      exec: () => Promise.reject(new Error('Built-in benchmark must not execute external tools')),
    };

    const results = [];
    results.push(await measure(
      'frontend line lookup',
      Buffer.byteLength(frontendSource),
      FRONTEND_REFERENCES,
      () => sourceFindings('src/client.ts', frontendSource, browserProject),
    ));
    results.push(await measure(
      'workflow expression lookup',
      Buffer.byteLength(workflowSource),
      WORKFLOW_EXPRESSIONS,
      () => findUntrustedExpressions(workflowSource),
    ));
    results.push(await measure(
      'two built-in scanners end to end',
      endToEndBytes,
      E2E_FINDINGS_PER_SCANNER * 2 + 2,
      async () => (await runScan(scanOptions)).findings,
    ));

    process.stdout.write(`${formatTable(results)}\n\n`);
    process.stdout.write(`Node ${process.version}; ${process.platform}/${process.arch}; ${os.cpus()[0]?.model ?? 'unknown CPU'}\n`);
    process.stdout.write(`Fixed workload, ${WARMUP_RUNS} warmups and ${MEASURED_RUNS} measured runs. No external scanners or network calls.\n`);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}

await benchmark();

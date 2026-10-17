import { describe, expect, it } from 'vitest';
import { auditWorkflow } from '../../src/scanners/workflow-audit/index.js';
import { findUntrustedExpressions } from '../../src/scanners/workflow-audit/rules/untrusted-contexts.js';

const audit = (source: string) => auditWorkflow('.github/workflows/ci.yml', source);
const ruleIds = (source: string) => audit(source).map((f) => f.ruleId);

describe('unpinned actions', () => {
  it('flags tag refs and accepts full SHAs and local actions', () => {
    const findings = audit(`
on: push
permissions: { contents: read }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v45
      - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.20
`);
    expect(findings.map((f) => [f.ruleId, f.severity, f.line])).toEqual([
      ['unpinned-action', 'low', 8],
      ['unpinned-action', 'medium', 9],
      ['unpinned-docker-action', 'medium', 12],
    ]);
  });

  it('checks reusable workflow references on jobs', () => {
    expect(ruleIds(`
on: push
permissions: {}
jobs:
  call:
    uses: someorg/shared/.github/workflows/build.yml@main
`)).toEqual(['unpinned-action']);
  });
});

describe('pull_request_target', () => {
  it('flags checkout of the PR head as critical', () => {
    const findings = audit(`
on: pull_request_target
permissions: { contents: read }
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1a4442cacd436585916779262731d5b162bc6ec7
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test
`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'pull-request-target-checkout', severity: 'critical', line: 8 });
  });

  it('flags gh pr checkout in a run step', () => {
    expect(ruleIds(`
on: { pull_request_target: { types: [opened] } }
permissions: { contents: read }
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr checkout \${{ github.event.pull_request.number }}
`)).toContain('pull-request-target-checkout');
  });

  it('reports a low note when the trigger is used safely', () => {
    expect(ruleIds(`
on: pull_request_target
permissions: { pull-requests: read }
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo labelling
`)).toEqual(['pull-request-target-trigger']);
  });

  it('flags write scopes on pull_request_target jobs', () => {
    expect(ruleIds(`
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    permissions: { pull-requests: write, contents: read }
    steps:
      - run: echo hi
`)).toEqual(['pull-request-target-trigger', 'pull-request-target-write-token']);
  });
});

describe('permissions', () => {
  it('flags write-all at workflow and job level', () => {
    const findings = audit(`
on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    permissions: write-all
    steps: [{ run: echo }]
`);
    expect(findings.map((f) => [f.ruleId, f.line])).toEqual([
      ['write-all-permissions', 3],
      ['write-all-permissions', 7],
    ]);
  });

  it('flags missing permissions once per workflow', () => {
    expect(ruleIds(`
on: push
jobs:
  a: { runs-on: ubuntu-latest, steps: [{ run: echo a }] }
  b: { runs-on: ubuntu-latest, steps: [{ run: echo b }] }
`)).toEqual(['missing-permissions']);
  });

  it('accepts per-job permissions without a top-level block', () => {
    expect(ruleIds(`
on: push
jobs:
  a: { runs-on: ubuntu-latest, permissions: { contents: read }, steps: [{ run: echo a }] }
`)).toEqual([]);
  });
});

describe('script injection', () => {
  it('points at the exact line inside a block script', () => {
    const findings = audit(`
on: issues
permissions: { contents: read }
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "start"
          echo "\${{ github.event.issue.title }}"
`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'script-injection', severity: 'high', line: 10 });
  });

  it('checks actions/github-script and ignores values passed through env', () => {
    expect(ruleIds(`
on: issue_comment
permissions: { contents: read }
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: console.log("\${{ github.event.comment.body }}")
      - env:
          BODY: \${{ github.event.comment.body }}
        run: echo "$BODY"
`)).toEqual(['script-injection']);
  });

  it('recognises array and wildcard context forms', () => {
    const script = 'echo ${{ github.event.commits[0].message }} ${{ github.event.pages.*.page_name }} ${{ github.sha }}';
    expect(findUntrustedExpressions(script).map((h) => h.expression)).toEqual([
      '${{ github.event.commits[0].message }}',
      '${{ github.event.pages.*.page_name }}',
    ]);
  });
});

describe('parse errors', () => {
  it('reports invalid YAML as a low finding instead of throwing', () => {
    const findings = audit('on: [push\njobs: {');
    expect(findings[0]).toMatchObject({ ruleId: 'workflow-parse-error', severity: 'low' });
  });
});

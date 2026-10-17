import type { RuleHit, WorkflowRule } from '../rule.js';
import type { YamlPath } from '../workflow.js';
import { findUntrustedExpressions } from './untrusted-contexts.js';

const REFERENCES = [
  'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections',
  'https://securitylab.github.com/resources/github-actions-untrusted-input/',
];

export const scriptInjection: WorkflowRule = (workflow) =>
  workflow.jobs.flatMap((job) =>
    job.steps.flatMap((step) => {
      const scripts: { source: string; path: YamlPath; kind: string }[] = [];
      if (step.run) scripts.push({ source: step.run, path: [...step.path, 'run'], kind: 'run script' });
      const githubScript = step.with.script;
      if (step.uses?.startsWith('actions/github-script') && typeof githubScript === 'string') {
        scripts.push({ source: githubScript, path: [...step.path, 'with', 'script'], kind: 'github-script' });
      }

      return scripts.flatMap(({ source, path, kind }) =>
        findUntrustedExpressions(source).map(
          ({ expression, lineIndex }): RuleHit => ({
            ruleId: 'script-injection',
            title: 'Untrusted input interpolated into a script',
            severity: 'high',
            line: workflow.lineInValue(path, lineIndex),
            message: `Job "${job.id}" expands ${expression} directly inside a ${kind}. Anyone who can open an issue, PR or comment can inject shell or JavaScript that runs with this job's token and secrets.`,
            remediation:
              'Move the value into an environment variable (env: TITLE: ${{ ... }}) and reference it as "$TITLE" in the script, so it is treated as data and never parsed as code.',
            references: REFERENCES,
          }),
        ),
      );
    }),
  );

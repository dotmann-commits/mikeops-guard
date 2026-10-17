import type { RuleHit, WorkflowRule } from '../rule.js';
import type { WorkflowStep } from '../workflow.js';

const PR_HEAD_REF =
  /github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs\/pull\/|github\.event\.number|github\.event\.pull_request\.number/;
const WORKFLOW_RUN_HEAD = /github\.event\.workflow_run\.head_(?:sha|branch)/;
const SHELL_CHECKOUT = /\b(?:git\s+(?:fetch|checkout|switch)|gh\s+pr\s+checkout)\b/;
const REFERENCES = ['https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/'];

function checksOutHead(step: WorkflowStep, headPattern: RegExp): boolean {
  if (step.uses?.startsWith('actions/checkout')) {
    const ref = step.with.ref;
    const repository = step.with.repository;
    return (typeof ref === 'string' && headPattern.test(ref)) || (typeof repository === 'string' && /head\.repo/.test(repository));
  }
  return step.run !== undefined && SHELL_CHECKOUT.test(step.run) && headPattern.test(step.run);
}

export const pullRequestTarget: WorkflowRule = (workflow) => {
  const hits: RuleHit[] = [];
  const isPrTarget = workflow.triggers.has('pull_request_target');
  const isWorkflowRun = workflow.triggers.has('workflow_run');

  for (const job of workflow.jobs) {
    for (const step of job.steps) {
      if (isPrTarget && checksOutHead(step, PR_HEAD_REF)) {
        hits.push({
          ruleId: 'pull-request-target-checkout',
          title: 'pull_request_target checks out untrusted PR code',
          severity: 'critical',
          line: workflow.lineAt(step.path),
          message: `Job "${job.id}" runs on pull_request_target, which has repository secrets and a write token, and checks out the pull request head. Any build, install or test step can then run code from a fork.`,
          remediation:
            'Use the pull_request trigger for untrusted code. If you need pull_request_target, never check out the PR head, or split the work into an unprivileged pull_request workflow plus a privileged workflow_run that only handles artifacts.',
          references: REFERENCES,
        });
      }
      if (isWorkflowRun && checksOutHead(step, WORKFLOW_RUN_HEAD)) {
        hits.push({
          ruleId: 'workflow-run-checkout',
          title: 'workflow_run checks out code from the triggering run',
          severity: 'high',
          line: workflow.lineAt(step.path),
          message: `Job "${job.id}" runs on workflow_run with secrets and checks out the head of the triggering run, which can come from a fork.`,
          remediation: 'Treat artifacts and code from the triggering run as untrusted. Do not execute them in the privileged workflow.',
          references: REFERENCES,
        });
      }
    }
  }

  if (isPrTarget && hits.length === 0) {
    hits.push({
      ruleId: 'pull-request-target-trigger',
      title: 'Workflow uses the pull_request_target trigger',
      severity: 'low',
      line: workflow.lineAt(['on']),
      message:
        'pull_request_target runs with secrets and a write token even for pull requests from forks. No head checkout was found, but review every step for use of PR data.',
      remediation: 'Prefer the pull_request trigger unless the workflow only labels or comments, and keep permissions minimal.',
      references: REFERENCES,
    });
  }
  return hits;
};

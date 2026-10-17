import type { RuleHit, WorkflowRule } from '../rule.js';
import { isRecord, type YamlPath } from '../workflow.js';

const REFERENCES = [
  'https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token',
];

function writeScopes(permissions: unknown): string[] {
  if (!isRecord(permissions)) return [];
  return Object.entries(permissions)
    .filter(([, level]) => level === 'write')
    .map(([scope]) => scope);
}

export const broadPermissions: WorkflowRule = (workflow) => {
  const hits: RuleHit[] = [];
  const writeAll = (where: string, path: YamlPath): RuleHit => ({
    ruleId: 'write-all-permissions',
    title: 'GITHUB_TOKEN granted write-all',
    severity: 'high',
    line: workflow.lineAt(path),
    message: `${where} sets permissions: write-all, so every step and action can push code, edit releases and change repository settings that the token covers.`,
    remediation: 'Replace write-all with the specific scopes the job needs, for example permissions: { contents: read }.',
    references: REFERENCES,
  });

  if (workflow.permissions === 'write-all') hits.push(writeAll('The workflow', ['permissions']));
  for (const job of workflow.jobs) {
    if (job.permissions === 'write-all') hits.push(writeAll(`Job "${job.id}"`, [...job.path, 'permissions']));
  }

  if (workflow.triggers.has('pull_request_target')) {
    for (const job of workflow.jobs) {
      const scopes = writeScopes(job.hasPermissions ? job.permissions : workflow.permissions);
      if (scopes.length === 0) continue;
      hits.push({
        ruleId: 'pull-request-target-write-token',
        title: 'Write token on a pull_request_target job',
        severity: 'medium',
        line: workflow.lineAt(job.hasPermissions ? [...job.path, 'permissions'] : ['permissions']),
        message: `Job "${job.id}" runs for fork pull requests with write access to: ${scopes.join(', ')}.`,
        remediation: 'Grant write scopes only to the job that needs them and keep the rest read-only.',
        references: REFERENCES,
      });
    }
  }

  const jobsWithoutPermissions = workflow.jobs.filter((job) => !job.hasPermissions && !job.uses);
  if (!workflow.hasPermissions && jobsWithoutPermissions.length > 0) {
    hits.push({
      ruleId: 'missing-permissions',
      title: 'No explicit GITHUB_TOKEN permissions',
      severity: 'low',
      line: workflow.lineAt(['jobs']),
      message: `No top-level permissions block, and ${jobsWithoutPermissions.length} job(s) do not set their own. They inherit the repository default, which is read and write on older repositories and organisations.`,
      remediation: 'Add a top-level permissions: { contents: read } block and widen it per job only where needed.',
      references: REFERENCES,
    });
  }
  return hits;
};

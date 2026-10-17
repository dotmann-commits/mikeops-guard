import type { RuleHit, WorkflowRule } from '../rule.js';
import type { YamlPath } from '../workflow.js';

const FULL_SHA = /^[0-9a-f]{40}$/i;
const FIRST_PARTY_OWNERS = new Set(['actions', 'github']);
const REFERENCES = [
  'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions',
];

export const unpinnedActions: WorkflowRule = (workflow) => {
  const refs: { uses: string; path: YamlPath }[] = [
    ...workflow.jobs.flatMap((job) => (job.uses ? [{ uses: job.uses, path: [...job.path, 'uses'] }] : [])),
    ...workflow.jobs.flatMap((job) =>
      job.steps.flatMap((step) => (step.uses ? [{ uses: step.uses, path: [...step.path, 'uses'] }] : [])),
    ),
  ];
  return refs.flatMap(({ uses, path }) => {
    const hit = checkReference(uses.trim());
    return hit ? [{ ...hit, line: workflow.lineAt(path) }] : [];
  });
};

function checkReference(uses: string): Omit<RuleHit, 'line'> | null {
  if (uses.startsWith('./')) return null;

  if (uses.startsWith('docker://')) {
    if (uses.includes('@sha256:')) return null;
    return {
      ruleId: 'unpinned-docker-action',
      title: 'Docker action not pinned to a digest',
      severity: 'medium',
      message: `"${uses}" uses a mutable image tag. Whoever controls the tag controls what runs in your job.`,
      remediation: 'Pin the image by digest, for example docker://image@sha256:<digest>.',
      references: REFERENCES,
    };
  }

  const at = uses.lastIndexOf('@');
  const target = at === -1 ? uses : uses.slice(0, at);
  const ref = at === -1 ? '' : uses.slice(at + 1);
  if (FULL_SHA.test(ref)) return null;

  const owner = target.split('/')[0] ?? '';
  const firstParty = FIRST_PARTY_OWNERS.has(owner.toLowerCase());
  return {
    ruleId: 'unpinned-action',
    title: firstParty ? 'GitHub-owned action not pinned to a commit SHA' : 'Third-party action not pinned to a commit SHA',
    severity: firstParty ? 'low' : 'medium',
    message: `"${uses}" points at ${ref ? `the mutable ref "${ref}"` : 'no ref at all'}. A moved tag or compromised maintainer account changes the code your workflow runs, with access to its secrets.`,
    remediation: `Pin to a full 40-character commit SHA and keep the version as a comment, for example uses: ${target}@<sha> # ${ref || 'vX.Y.Z'}. Dependabot can keep SHA pins up to date.`,
    references: REFERENCES,
  };
}

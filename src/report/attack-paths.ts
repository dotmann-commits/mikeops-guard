import type { Finding, Severity } from '../core/types.js';
import { severityRank } from '../core/policy.js';

export interface AttackPathStage {
  label: string;
  scanner: Finding['scanner'];
  ruleId: string;
  file?: string;
  line?: number;
  fingerprint: string;
}

export interface AttackPath {
  id: string;
  title: string;
  severity: Severity;
  summary: string;
  stages: AttackPathStage[];
}

function strongest(findings: readonly Finding[], predicate: (finding: Finding) => boolean): Finding | undefined {
  return findings
    .filter((finding) => severityRank(finding.severity) >= severityRank('medium') && predicate(finding))
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))[0];
}

function stage(label: string, source: Finding): AttackPathStage {
  return {
    label,
    scanner: source.scanner,
    ruleId: source.ruleId,
    ...(source.file ? { file: source.file } : {}),
    ...(source.line ? { line: source.line } : {}),
    fingerprint: source.fingerprint,
  };
}

function pathSeverity(sources: readonly Finding[]): Severity {
  return [...sources].sort((left, right) => severityRank(right.severity) - severityRank(left.severity))[0]?.severity ?? 'medium';
}

export function correlateAttackPaths(findings: readonly Finding[]): AttackPath[] {
  const agent = strongest(findings, (finding) => finding.scanner === 'ai-supply-chain');
  const workflow = strongest(findings, (finding) => finding.scanner === 'workflow-audit');
  const secret = strongest(findings, (finding) => finding.scanner === 'gitleaks');
  const application = strongest(findings, (finding) => finding.scanner === 'app-security');
  const paths: AttackPath[] = [];

  if (agent && workflow && secret) paths.push({
    id: 'agent-ci-secret',
    title: 'AI toolchain compromise can reach CI credentials',
    severity: pathSeverity([agent, workflow, secret]),
    summary: 'Correlated evidence suggests a poisoned agent instruction or tool could influence a risky workflow and expose a detected repository credential. This is a potential path, not proof of exploitation.',
    stages: [stage('Agent/tooling entry', agent), stage('CI execution', workflow), stage('Credential impact', secret)],
  });
  if (agent && workflow && application) paths.push({
    id: 'agent-ci-application',
    title: 'AI-generated change can reach an exposed application boundary',
    severity: pathSeverity([agent, workflow, application]),
    summary: 'Correlated evidence suggests agent-controlled changes could pass through a risky workflow into an application or data-control weakness. Validate reachability before treating it as confirmed.',
    stages: [stage('Agent/tooling entry', agent), stage('CI execution', workflow), stage('Application impact', application)],
  });

  if (paths.length === 0) {
    const pairs: Array<[string, string, string, Finding | undefined, string, Finding | undefined]> = [
      ['agent-ci', 'AI toolchain finding can influence a risky CI boundary', 'Agent/tooling findings and workflow findings coexist and may form a path if the affected files are used together.', agent, 'CI execution', workflow],
      ['ci-secret', 'Risky CI behavior can expose a detected credential', 'Workflow and credential findings coexist; verify whether the workflow can access the affected secret.', workflow, 'Credential impact', secret],
      ['ci-application', 'Risky CI behavior can deploy an application weakness', 'Workflow and application findings coexist; verify whether this workflow deploys the affected component.', workflow, 'Application impact', application],
      ['agent-secret', 'AI toolchain compromise can expose a detected credential', 'Agent/tooling and credential findings coexist; verify whether the agent can read or transmit the affected value.', agent, 'Credential impact', secret],
      ['agent-application', 'AI-generated change can reach an application weakness', 'Agent/tooling and application findings coexist; verify whether the affected instructions can modify this component.', agent, 'Application impact', application],
    ];
    let added = 0;
    for (const [id, title, summary, first, secondLabel, second] of pairs) {
      if (!first || !second) continue;
      paths.push({
        id, title, summary: `${summary} This is a potential path, not proof of exploitation.`,
        severity: pathSeverity([first, second]),
        stages: [stage(first === agent ? 'Agent/tooling entry' : 'CI execution', first), stage(secondLabel, second)],
      });
      added++;
      if (added === 2) break;
    }
  }
  return paths;
}

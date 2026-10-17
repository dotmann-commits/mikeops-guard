import type { Severity } from '../../core/types.js';
import type { Workflow } from './workflow.js';

export interface RuleHit {
  ruleId: string;
  title: string;
  severity: Severity;
  line?: number;
  message: string;
  remediation: string;
  references: string[];
}

export type WorkflowRule = (workflow: Workflow) => RuleHit[];

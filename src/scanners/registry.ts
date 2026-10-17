import type { Scanner } from '../core/scanner.js';
import { actionlintScanner } from './actionlint.js';
import { dependenciesScanner } from './dependencies.js';
import { gitleaksScanner } from './gitleaks.js';
import { hadolintScanner } from './hadolint.js';
import { trivyConfigScanner } from './trivy-config.js';
import { workflowAuditScanner } from './workflow-audit/index.js';

/** Order here is the order scanners appear in reports. Add new scanners to this list. */
export const SCANNERS: readonly Scanner[] = [
  gitleaksScanner,
  workflowAuditScanner,
  actionlintScanner,
  hadolintScanner,
  trivyConfigScanner,
  dependenciesScanner,
];

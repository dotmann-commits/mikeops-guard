import { z } from 'zod';
import { SEVERITIES } from '../core/types.js';

const severity = z.enum(SEVERITIES);
const enabled = z.boolean().default(true);

// prefault() runs the inner defaults when a section is missing; default() would not.
const toggle = z.strictObject({ enabled }).prefault({});

export const configSchema = z.strictObject({
  failOn: z.enum([...SEVERITIES, 'none']).default('high'),
  requireTools: z.boolean().default(false),
  timeoutSeconds: z.number().int().positive().max(3600).default(300),
  exclude: z.array(z.string().min(1)).default([]),
  scanners: z
    .strictObject({
      hadolint: toggle,
      'trivy-config': toggle,
      actionlint: toggle,
      'workflow-audit': toggle,
      gitleaks: z
        .strictObject({ enabled, mode: z.enum(['auto', 'git', 'dir']).default('auto') })
        .prefault({}),
      dependencies: z
        .strictObject({ enabled, engine: z.enum(['osv-scanner', 'trivy']).default('osv-scanner') })
        .prefault({}),
      'app-security': toggle,
    })
    .prefault({}),
  ignore: z
    .array(
      z.strictObject({
        rule: z.string().min(1),
        path: z.string().min(1).optional(),
        reason: z.string().optional(),
      }),
    )
    .default([]),
  severityOverrides: z.record(z.string().min(1), severity).default({}),
  explain: z
    .strictObject({
      enabled: z.boolean().default(false),
      host: z.url({ protocol: /^https?$/ }).default('http://127.0.0.1:11434'),
      model: z.string().min(1).default('llama3.2:3b'),
      maxFindings: z.number().int().min(1).max(100).default(10),
      timeoutSeconds: z.number().int().positive().max(600).default(120),
    })
    .prefault({}),
});

export type GuardConfig = z.output<typeof configSchema>;
export type ConfigInput = z.input<typeof configSchema>;
export type IgnoreRule = GuardConfig['ignore'][number];

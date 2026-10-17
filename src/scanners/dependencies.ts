import { z } from 'zod';
import type { ScanContext, Scanner } from '../core/scanner.js';
import type { NewFinding } from '../core/types.js';
import { definedOnly, parseJson, relativeToRoot, runTool, severityFromCvss, severityFromLabel } from './shared.js';
import { skipDirArgs } from './trivy-config.js';

const osvVulnSchema = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string()).nullish(),
  database_specific: z.object({ severity: z.string().optional() }).loose().nullish(),
  affected: z
    .array(
      z.object({
        package: z.object({ name: z.string().optional() }).optional(),
        ranges: z.array(z.object({ type: z.string(), events: z.array(z.record(z.string(), z.string())) })).nullish(),
      }),
    )
    .nullish(),
});

const osvSchema = z.object({
  results: z
    .array(
      z.object({
        source: z.object({ path: z.string() }),
        packages: z
          .array(
            z.object({
              package: z.object({ name: z.string(), version: z.string().optional(), ecosystem: z.string() }),
              vulnerabilities: z.array(osvVulnSchema).nullish(),
              groups: z
                .array(z.object({ ids: z.array(z.string()), aliases: z.array(z.string()).nullish(), max_severity: z.string().optional() }))
                .nullish(),
            }),
          )
          .nullish(),
      }),
    )
    .nullish(),
});

type OsvVuln = z.infer<typeof osvVulnSchema>;

// GIT ranges hold commit hashes, which are useless as an upgrade target for a package manager.
const VERSION_RANGE_TYPES = new Set(['ECOSYSTEM', 'SEMVER']);

function fixedVersion(vuln: OsvVuln, packageName: string): string | undefined {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name && affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      if (!VERSION_RANGE_TYPES.has(range.type)) continue;
      const fixed = range.events.find((event) => event.fixed)?.fixed;
      if (fixed) return fixed;
    }
  }
  return undefined;
}

/** osv-scanner groups aliases of the same issue. One finding per group avoids double counting. */
export function parseOsv(stdout: string, root: string): NewFinding[] {
  const report = parseJson(stdout, osvSchema, 'osv-scanner');
  return (report.results ?? []).flatMap((result) =>
    (result.packages ?? []).flatMap((pkg) => {
      const vulns = new Map((pkg.vulnerabilities ?? []).map((v) => [v.id, v]));
      const groups = pkg.groups ?? [...vulns.keys()].map((id) => ({ ids: [id], aliases: undefined, max_severity: undefined }));
      return groups.flatMap((group) => {
        const primary = group.ids.map((id) => vulns.get(id)).find((v) => v !== undefined);
        if (!primary) return [];
        const score = Number.parseFloat(group.max_severity ?? '');
        const severity = Number.isFinite(score) ? severityFromCvss(score) : severityFromLabel(primary.database_specific?.severity);
        const fixed = fixedVersion(primary, pkg.package.name);
        const aliases = [...group.ids, ...(group.aliases ?? []), ...(primary.aliases ?? [])];
        const id = aliases.find((i) => i.startsWith('CVE-')) ?? primary.id;
        return [
          definedOnly({
            scanner: 'dependencies' as const,
            ruleId: id,
            title: `${pkg.package.name}@${pkg.package.version ?? '?'}: ${primary.summary ?? id}`,
            severity,
            category: 'dependency' as const,
            file: relativeToRoot(root, result.source.path),
            message: `${pkg.package.ecosystem} package ${pkg.package.name} ${pkg.package.version ?? ''} is affected by ${group.ids.join(', ')}.`.replace(/\s+/g, ' '),
            remediation: fixed ? `Upgrade ${pkg.package.name} to ${fixed} or later.` : 'No fixed version is published yet. Check the advisory for a workaround.',
            references: [`https://osv.dev/vulnerability/${primary.id}`],
          }),
        ];
      });
    }),
  );
}

const trivyFsSchema = z.object({
  Results: z
    .array(
      z.object({
        Target: z.string(),
        Vulnerabilities: z
          .array(
            z.object({
              VulnerabilityID: z.string(),
              PkgName: z.string(),
              InstalledVersion: z.string().optional(),
              FixedVersion: z.string().optional(),
              Severity: z.string(),
              Title: z.string().optional(),
              PrimaryURL: z.string().optional(),
            }),
          )
          .nullish(),
      }),
    )
    .nullish(),
});

export function parseTrivyFs(stdout: string, root: string): NewFinding[] {
  const report = parseJson(stdout, trivyFsSchema, 'trivy fs');
  return (report.Results ?? []).flatMap((result) =>
    (result.Vulnerabilities ?? []).map((v) =>
      definedOnly({
        scanner: 'dependencies' as const,
        ruleId: v.VulnerabilityID,
        title: `${v.PkgName}@${v.InstalledVersion ?? '?'}: ${v.Title ?? v.VulnerabilityID}`,
        severity: severityFromLabel(v.Severity),
        category: 'dependency' as const,
        file: relativeToRoot(root, result.Target),
        message: `${v.PkgName} ${v.InstalledVersion ?? ''} is affected by ${v.VulnerabilityID}.`.replace(/\s+/g, ' '),
        remediation: v.FixedVersion ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later.` : 'No fixed version is published yet.',
        references: v.PrimaryURL ? [v.PrimaryURL] : [],
      }),
    ),
  );
}

// osv-scanner exits 1 when vulnerabilities are found and 128 when no lockfiles exist.
const OSV_OK_CODES = [0, 1, 128];

async function runOsv(ctx: ScanContext): Promise<NewFinding[]> {
  const { code, stdout } = await runTool(ctx, ['scan', 'source', '--recursive', '--format', 'json', '.'], OSV_OK_CODES);
  if (code === 128 || !stdout.trim()) return [];
  return parseOsv(stdout, ctx.root);
}

async function runTrivyFs(ctx: ScanContext): Promise<NewFinding[]> {
  const { stdout } = await runTool(ctx, [
    'fs',
    '--scanners',
    'vuln',
    '--format',
    'json',
    '--quiet',
    '--exit-code',
    '0',
    ...skipDirArgs(ctx.config.exclude),
    '.',
  ]);
  return parseTrivyFs(stdout, ctx.root);
}

export const dependenciesScanner: Scanner = {
  id: 'dependencies',
  title: 'Vulnerable dependencies',
  category: 'dependency',
  tool: (config) => (config.scanners.dependencies.engine === 'trivy' ? 'trivy' : 'osv-scanner'),
  skipReason: () => null,
  run: (ctx) => (ctx.config.scanners.dependencies.engine === 'trivy' ? runTrivyFs(ctx) : runOsv(ctx)),
};

import path from 'node:path';
import type { NewFinding } from '../../core/types.js';

/** Prefixes that frameworks compile into the browser bundle: anything with these names is public. */
const PUBLIC_PREFIX = '(?:VITE_|NEXT_PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)';
const SENSITIVE = '(?:SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|PASSWD)';
const PUBLIC_SECRET_NAME = new RegExp(String.raw`^${PUBLIC_PREFIX}[A-Z0-9_]*${SENSITIVE}[A-Z0-9_]*$`);
const ENV_ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;
const CODE_REFERENCE = new RegExp(String.raw`(?:import\.meta\.env|process\.env)\.(${PUBLIC_PREFIX}[A-Z0-9_]*${SENSITIVE}[A-Z0-9_]*)`, 'g');
const SERVICE_ROLE = /SUPABASE_SERVICE_ROLE(?:_KEY)?|SERVICE_ROLE_KEY|serviceRoleKey|service_role_key/;

/** Path segments that hold code which runs on a server, never in the browser. */
const SERVER_SEGMENTS = new Set([
  'api', 'server', 'servers', 'functions', 'supabase', 'scripts', 'backend', 'edge-functions', 'lambda', 'lambdas',
  'workers', 'worker', 'prisma', 'migrations', 'test', 'tests', '__tests__', 'e2e', 'cypress', 'netlify', 'cron',
]);

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split('\n').length;
}

function publicSecretFinding(file: string, line: number, name: string, where: 'env' | 'code'): NewFinding {
  const serviceRole = /SERVICE_ROLE/.test(name);
  return {
    scanner: 'app-security',
    ruleId: 'public-env-secret',
    title: `${name} would be shipped to every browser`,
    severity: serviceRole ? 'critical' : 'high',
    category: 'application',
    file,
    line,
    message:
      `${name} uses a prefix that the framework compiles into the frontend bundle, and its name says it holds a ` +
      `${serviceRole ? 'Supabase service role key, which bypasses all Row Level Security' : 'secret'}. ` +
      (where === 'env' ? 'It is defined in an environment file.' : 'It is read by frontend code.'),
    remediation:
      'Move the value to a server-only variable without the public prefix, use it only in server code (API routes, edge functions), and rotate it if it was ever deployed.',
    references: ['https://supabase.com/docs/guides/api/api-keys', 'https://vite.dev/guide/env-and-mode'],
  };
}

/** Names only: values are never read into a finding. */
export function envFileFindings(file: string, source: string): NewFinding[] {
  return source.split('\n').flatMap((text, i) => {
    const name = ENV_ASSIGNMENT.exec(text)?.[1];
    return name && PUBLIC_SECRET_NAME.test(name) ? [publicSecretFinding(file, i + 1, name, 'env')] : [];
  });
}

export function isServerPath(file: string): boolean {
  if (/\.server\.[cm]?[jt]sx?$/.test(file) || /(?:^|\/)(?:middleware|\+server)\.[cm]?[jt]s$/.test(file)) return true;
  return file.split('/').slice(0, -1).some((segment) => SERVER_SEGMENTS.has(segment));
}

/**
 * Code that only ever runs on a server, whatever the folder: TanStack Start server routes and server functions,
 * Remix and React Router loaders and actions, HTTP method handlers, and "use server" modules.
 */
const SERVER_MARKERS = new RegExp(
  [
    String.raw`^\s*['"]use server['"]`,
    String.raw`\bserver\s*:\s*\{\s*handlers\b`,
    String.raw`\bcreateServer(?:Fn|OnlyFn)\s*\(`,
    String.raw`^export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|loader|action)\b`,
    String.raw`^export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE|loader|action)\s*=`,
  ].join('|'),
  'm',
);

export interface ProjectKind {
  /** The nearest package.json depends on a frontend framework or bundler. A Node CLI or library is not a web app. */
  browser: boolean;
  /**
   * True for Next.js, where components run on the server unless the file says "use client". Other frameworks
   * (TanStack Start, Remix, SvelteKit, Vite, CRA, Expo) ship component code to the browser.
   */
  clientDirective: boolean;
}

/** Does this file run in the browser? Server folders and server-only code never do, nor does anything outside a web app. */
export function runsInBrowser(file: string, source: string, project: ProjectKind): boolean {
  if (!project.browser || isServerPath(file) || SERVER_MARKERS.test(source)) return false;
  if (project.clientDirective) return /^\s*['"]use client['"]/m.test(source.slice(0, 500));
  return true;
}

export function sourceFindings(file: string, source: string, project: ProjectKind): NewFinding[] {
  const findings: NewFinding[] = [];
  for (const match of source.matchAll(CODE_REFERENCE)) {
    findings.push(publicSecretFinding(file, lineOf(source, match.index), match[1] ?? '', 'code'));
  }
  const serviceRole = SERVICE_ROLE.exec(source);
  if (serviceRole && runsInBrowser(file, source, project)) {
    findings.push({
      scanner: 'app-security',
      ruleId: 'service-role-in-frontend',
      title: 'Supabase service role key used in code that runs in the browser',
      severity: 'critical',
      category: 'application',
      file,
      line: lineOf(source, serviceRole.index),
      message: `${path.posix.basename(file)} refers to the service role key and is not in a server-only location. The service role bypasses every Row Level Security policy, so anyone who opens the app can read and change all data.`,
      remediation: 'Use the anon key in the browser and move service role operations to a server function or API route. Rotate the key if this was ever deployed.',
      references: ['https://supabase.com/docs/guides/api/api-keys'],
    });
  }
  return findings;
}

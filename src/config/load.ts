import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { z } from 'zod';
import { ConfigError, errorMessage } from '../core/errors.js';
import { configSchema, type GuardConfig } from './schema.js';

export const CONFIG_FILENAMES = ['.mikeops-guard.yml', '.mikeops-guard.yaml', '.mikeops-guard.json'] as const;

export interface LoadedConfig {
  config: GuardConfig;
  /** Absolute path of the file that was read, or undefined when defaults are used. */
  source?: string;
  /** Settings that were refused for safety, explained for the user. */
  warnings: string[];
}

const DEFAULT_EXPLAIN_HOST = configSchema.parse({}).explain.host;

function isLoopbackHost(url: string): boolean {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || /^127(?:\.\d{1,3}){3}$/.test(host);
}

/**
 * A config found inside the scanned repository is written by whoever controls that repository. It may tune the scan,
 * but it must not send finding details off this machine, so its Ollama host must be local.
 */
function restrictRepositoryConfig(config: GuardConfig, source: string): LoadedConfig {
  if (isLoopbackHost(config.explain.host)) return { config, source, warnings: [] };
  return {
    config: { ...config, explain: { ...config.explain, host: DEFAULT_EXPLAIN_HOST } },
    source,
    warnings: [
      `Ignored explain.host "${config.explain.host}" from the repository's config: a config inside the scanned repository ` +
        `may only use a local Ollama host, so finding details never leave this machine. To use a remote host, pass a ` +
        `trusted config with --config. Using ${DEFAULT_EXPLAIN_HOST}.`,
    ],
  };
}

/**
 * An explicit --config path must exist. Otherwise only the target root is searched,
 * so the policy always belongs to the repo being scanned, never to wherever the CLI runs.
 */
export async function loadConfig(options: { explicitPath?: string; root: string; cwd: string }): Promise<LoadedConfig> {
  if (options.explicitPath) {
    const file = path.resolve(options.cwd, options.explicitPath);
    const raw = await readConfigFile(file);
    if (raw === null) throw new ConfigError(`Config file not found: ${file}`);
    return { config: parseConfig(raw, file), source: file, warnings: [] }; // chosen by the user: trusted
  }

  for (const name of CONFIG_FILENAMES) {
    const file = path.join(options.root, name);
    const raw = await readConfigFile(file);
    if (raw !== null) return restrictRepositoryConfig(parseConfig(raw, file), file);
  }
  return { config: configSchema.parse({}), warnings: [] };
}

export function parseConfig(raw: string, source = 'config'): GuardConfig {
  let data: unknown;
  try {
    // YAML is a superset of JSON, so one parser covers every supported file type.
    data = parseYaml(raw) ?? {};
  } catch (error) {
    throw new ConfigError(`Could not parse ${source}: ${errorMessage(error)}`);
  }
  const result = configSchema.safeParse(data);
  if (!result.success) {
    throw new ConfigError(`Invalid config in ${source}:\n${formatIssues(result.error)}`);
  }
  return result.data;
}

function formatIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const where = issue.path.length > 0 ? issue.path.join('.') : '(root)';
      return `  - ${where}: ${issue.message}`;
    })
    .join('\n');
}

async function readConfigFile(file: string): Promise<string | null> {
  try {
    return await readFile(file, 'utf8');
  } catch (error) {
    if (isNotFound(error)) return null;
    throw new ConfigError(`Could not read ${file}: ${errorMessage(error)}`);
  }
}

function isNotFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

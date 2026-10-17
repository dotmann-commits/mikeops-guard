import { readFileSync } from 'node:fs';

interface PackageJson {
  version: string;
}

/** Read at runtime so the version has one source of truth, package.json. */
export function toolVersion(): string {
  const raw = readFileSync(new URL('../../package.json', import.meta.url), 'utf8');
  return (JSON.parse(raw) as PackageJson).version;
}

import type { GuardConfig } from '../../config/schema.js';
import { SCANNER_IDS, type ScannerId } from '../../core/types.js';
import type { ScanOptions } from '../args.js';

/** CLI flags win over the config file. Returns a new config, the input is not changed. */
export function applyCliOverrides(config: GuardConfig, options: ScanOptions): GuardConfig {
  return {
    ...config,
    scanners: setEnabled(config.scanners, (id, enabled) => isEnabled(id, enabled, options)),
    failOn: options.failOn ?? config.failOn,
    requireTools: options.requireTools || config.requireTools,
    explain: {
      ...config.explain,
      enabled: options.explain || config.explain.enabled,
      model: options.model ?? config.explain.model,
    },
  };
}

type Toggles = Record<ScannerId, { enabled: boolean }>;

function setEnabled<T extends Toggles>(scanners: T, decide: (id: ScannerId, enabled: boolean) => boolean): T {
  const next: T = { ...scanners };
  for (const id of SCANNER_IDS) {
    next[id] = { ...scanners[id], enabled: decide(id, scanners[id].enabled) };
  }
  return next;
}

function isEnabled(id: ScannerId, fromConfig: boolean, options: ScanOptions): boolean {
  if (options.skip?.includes(id)) return false;
  if (options.only) return options.only.includes(id);
  return fromConfig;
}

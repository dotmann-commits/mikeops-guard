import type { Report } from '../core/types.js';

export function renderJson(report: Report): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

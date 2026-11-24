import path from 'node:path';
import { EXIT_CODES } from '../../core/exit-codes.js';
import { scanRepositoryForMcp } from '../../mcp/scan.js';
import { renderAgentDirectives } from '../../report/agent.js';
import type { HookOptions } from '../args.js';
import type { CliIo } from '../io.js';

export async function hookCommand(options: HookOptions, io: CliIo): Promise<number> {
  const root = path.resolve(io.cwd, options.path);
  const result = await scanRepositoryForMcp(root, { path: '.', mode: 'fast', failOn: options.failOn, maxFindings: 100 });
  const output = renderAgentDirectives(result.findings, options.failOn);
  if (output === '') return result.status === 'incomplete' ? EXIT_CODES.scannerFailed : EXIT_CODES.pass;
  if (options.agent) {
    io.stderr(output);
    return EXIT_CODES.usage;
  }
  io.stdout(output);
  return EXIT_CODES.policyFailed;
}

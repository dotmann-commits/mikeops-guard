import { loadConfig } from '../../config/load.js';
import { errorMessage } from '../../core/errors.js';
import { execCommand } from '../../core/exec.js';
import { installHint, resolveBinary, TOOLS, type ToolName } from '../../core/tools.js';
import { OllamaClient } from '../../explain/ollama.js';
import type { CliIo } from '../io.js';

const VERSION_TIMEOUT_MS = 10_000;

async function toolVersion(binary: string, args: readonly string[], cwd: string): Promise<string> {
  try {
    const { stdout, stderr } = await execCommand(binary, args, { cwd, timeoutMs: VERSION_TIMEOUT_MS });
    const firstLine = (stdout || stderr).trim().split('\n')[0] ?? '';
    return firstLine.replace(/^version:?\s*/i, '');
  } catch (error) {
    return `found, but version check failed: ${errorMessage(error)}`;
  }
}

/** Reports what is installed. Always exits 0, because missing tools are skipped during scans. */
export async function doctorCommand(io: CliIo): Promise<number> {
  io.stdout('MikeOps Guard doctor\n\nScanners\n');
  for (const name of Object.keys(TOOLS) as ToolName[]) {
    const binary = resolveBinary(name, io.env.PATH ?? '');
    if (binary) {
      io.stdout(`  ok       ${name.padEnd(12)} ${await toolVersion(binary, TOOLS[name].versionArgs, io.cwd)}\n`);
    } else {
      io.stdout(`  missing  ${name.padEnd(12)} ${installHint(name)}\n`);
    }
  }

  const { config } = await loadConfig({ root: io.cwd, cwd: io.cwd });
  const client = new OllamaClient({ host: config.explain.host, model: config.explain.model, timeoutMs: VERSION_TIMEOUT_MS });
  const problem = await client.readiness();
  io.stdout(`\nLocal AI (optional, used by --explain)\n`);
  io.stdout(problem ? `  missing  ollama       ${problem}\n` : `  ok       ollama       ${config.explain.model} at ${config.explain.host}\n`);
  return 0;
}

import { CancelledError, ConfigError, GuardError, UsageError } from '../core/errors.js';
import { EXIT_CODES } from '../core/exit-codes.js';
import { parseCliArgs } from './args.js';
import { doctorCommand } from './commands/doctor.js';
import { initCommand } from './commands/init.js';
import { scanCommand, type ScanDependencies } from './commands/scan.js';
import { HELP_TEXT } from './help.js';
import type { CliIo } from './io.js';
import { toolVersion } from './version.js';

export async function main(argv: readonly string[], io: CliIo, deps: ScanDependencies = {}): Promise<number> {
  try {
    const parsed = parseCliArgs(argv, io.env, io.isTty);
    switch (parsed.command) {
      case 'help':
        io.stdout(HELP_TEXT);
        return EXIT_CODES.pass;
      case 'version':
        io.stdout(`${toolVersion()}\n`);
        return EXIT_CODES.pass;
      case 'doctor':
        return await doctorCommand(io);
      case 'init':
        return await initCommand(io);
      case 'scan':
        return await scanCommand(parsed.options, io, deps);
    }
  } catch (error) {
    if (error instanceof CancelledError) {
      io.stderr(`\nmikeops-guard: ${error.message}\n`);
      return EXIT_CODES.cancelled;
    }
    if (error instanceof GuardError) {
      io.stderr(`mikeops-guard: ${error.message}\n`);
      return error instanceof ConfigError || error instanceof UsageError ? EXIT_CODES.usage : EXIT_CODES.scannerFailed;
    }
    io.stderr(`mikeops-guard: unexpected error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
    return EXIT_CODES.scannerFailed;
  }
}

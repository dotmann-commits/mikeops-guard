#!/usr/bin/env node
import { main } from './main.js';
import { processIo } from './io.js';
import { installCancelHandlers } from './signals.js';

const controller = new AbortController();
installCancelHandlers(controller, process);
process.exitCode = await main(process.argv.slice(2), processIo, { signal: controller.signal });

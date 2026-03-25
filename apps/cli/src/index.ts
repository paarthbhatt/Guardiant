#!/usr/bin/env node
import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { reportCommand } from './commands/report.js';
import { configCommand } from './commands/config.js';
import { versionCommand } from './commands/version.js';

const program = new Command();

program
  .name('guardiant')
  .description('Agentic Security Platform for Vibe-Coded Applications')
  .version('0.1.0')
  .option('--verbose', 'Enable verbose logging', false)
  .option('--json', 'Output as JSON', false)
  .option('--config <path>', 'Path to config file');

// Register commands
program.addCommand(scanCommand);
program.addCommand(reportCommand);
program.addCommand(configCommand);
program.addCommand(versionCommand);

// Parse and execute
program.parse(process.argv);
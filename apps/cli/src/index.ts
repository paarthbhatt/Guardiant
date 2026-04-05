#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { scanCommand } from './commands/scan.js';
import { reportCommand } from './commands/report.js';
import { configCommand } from './commands/config.js';
import { versionCommand } from './commands/version.js';

// ASCII Art Banner
const BANNER = `
${chalk.cyan('░██████╗░██╗░░░██╗░█████╗░██████╗░██████╗░██╗░█████╗░███╗░░██╗████████╗')}
${chalk.cyan('██╔════╝░██║░░░██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗░██║╚══██╔══╝')}
${chalk.cyan('██║░░██╗░██║░░░██║███████║██████╔╝██║░░██║██║███████║██╔██╗██║░░░██║░░░')}
${chalk.cyan('██║░░╚██╗██║░░░██║██╔══██║██╔══██╗██║░░██║██║██╔══██║██║╚████║░░░██║░░░')}
${chalk.cyan('╚██████╔╝╚██████╔╝██║░░██║██║░░██║██████╔╝██║██║░░██║██║░╚███║░░░██║░░░')}
${chalk.cyan('░╚═════╝░░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░')}
${chalk.yellow('  AI-Generated Code Security Scanner v0.2.0')}
`;

const program = new Command();

program
  .name('guardiant')
  .description('🛡️ Agentic Security Platform for AI-Generated Applications')
  .version('0.2.0')
  .option('--verbose, -v', 'Enable debug logging', false)
  .option('--json', 'Output as JSON', false)
  .option('--config <path>', 'Path to config file')
  .option('--no-color', 'Disable colored output');

// Print banner on startup (except for help/version)
const args = process.argv.slice(2);
if (!args.includes('--help') && !args.includes('-h') && !args.includes('--version') && !args.includes('-V')) {
  console.log(BANNER);
}

// If no command provided, show help
if (process.argv.length <= 2 && !args.includes('--help') && !args.includes('-h')) {
  program.outputHelp();
  process.exit(0);
}

// Register commands
program.addCommand(scanCommand);
program.addCommand(reportCommand);
program.addCommand(configCommand);
program.addCommand(versionCommand);

// Parse arguments and handle errors gracefully
try {
  program.parse(process.argv);
} catch (error) {
  const isHelpRequest = args.includes('--help') || args.includes('-h');
  
  if (!isHelpRequest) {
    const message = error instanceof Error ? error.message : 'Unknown error occurred';
    console.error(chalk.red(`Error: ${message}`));
    console.error(chalk.gray('Run ' + chalk.cyan('guardiant --help') + ' for usage information'));
    process.exit(1);
  }
}


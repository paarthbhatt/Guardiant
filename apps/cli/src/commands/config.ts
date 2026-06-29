import { Command } from 'commander';
import chalk from 'chalk';
import Conf from 'conf';
import Table from 'cli-table3';

interface Config {
  anthropicApiKey?: string;
  openrouterApiKey?: string;
  geminiApiKey?: string;
  openaiApiKey?: string;
  zenmuxApiKey?: string;
  nvidiaApiKey?: string;
  defaultFormat?: 'json' | 'markdown' | 'html';
  defaultAudience?: 'executive' | 'developer' | 'security';
  maxConcurrency?: number;
  timeout?: number;
}

const config = new Conf<Config>({
  projectName: 'guardiant',
  defaults: {
    defaultFormat: 'markdown',
    defaultAudience: 'developer',
    maxConcurrency: 4,
    timeout: 600000,
  },
});

export const configCommand = new Command('config')
  .description('Manage Guardiant configuration');

// Add subcommands
configCommand
  .command('set <key> <value>')
  .description('Set a configuration value')
  .action((key: string, value: string) => {
    const validKeys = [
      'anthropicApiKey',
      'openrouterApiKey',
      'geminiApiKey',
      'openaiApiKey',
      'zenmuxApiKey',
      'nvidiaApiKey',
      'defaultFormat',
      'defaultAudience',
      'maxConcurrency',
      'timeout',
    ];

    if (!validKeys.includes(key)) {
      console.error(chalk.red(`Invalid config key: ${key}`));
      console.log(chalk.gray(`Valid keys: ${validKeys.join(', ')}`));
      process.exit(1);
    }

    // Handle special keys
    if (key === 'maxConcurrency' || key === 'timeout') {
      value = parseInt(value) as unknown as string;
    }

    config.set(key as keyof Config, value as never);
    console.log(chalk.green(`Set ${key} = ${value}`));
  });

configCommand
  .command('get <key>')
  .description('Get a configuration value')
  .action((key: string) => {
    const value = config.get(key as keyof Config);
    if (value === undefined) {
      console.log(chalk.gray(`Key "${key}" is not set`));
    } else {
      // Mask sensitive values
      if (key.toLowerCase().includes('key') || key.toLowerCase().includes('apikey')) {
        console.log(`${key} = ${chalk.gray('[HIDDEN]')}`);
      } else {
        console.log(`${key} = ${value}`);
      }
    }
  });

configCommand
  .command('list')
  .description('List all configuration values')
  .action(() => {
    console.log(chalk.bold('\nGuardiant Configuration'));
    console.log(chalk.gray('─'.repeat(50)));

    const table = new Table({
      head: ['Key', 'Value'],
      colWidths: [25, 50],
    });

    for (const [key, value] of Object.entries(config.store)) {
      // Mask sensitive values
      const displayValue =
        key.toLowerCase().includes('key') || key.toLowerCase().includes('apikey')
          ? chalk.gray('[HIDDEN]')
          : String(value);
      table.push([key, displayValue]);
    }

    console.log(table.toString());
    console.log(chalk.gray(`\nConfig file: ${config.path}`));
  });

configCommand
  .command('delete <key>')
  .description('Delete a configuration value')
  .action((key: string) => {
    if (config.has(key as keyof Config)) {
      config.delete(key as keyof Config);
      console.log(chalk.green(`Deleted ${key}`));
    } else {
      console.log(chalk.gray(`Key "${key}" is not set`));
    }
  });

configCommand
  .command('reset')
  .description('Reset all configuration to defaults')
  .option('-y, --yes', 'Skip confirmation')
  .action((options) => {
    if (!options.yes) {
      console.log(chalk.yellow('This will reset all configuration to defaults.'));
      console.log('Use --yes to confirm.');
      process.exit(0);
    }

    config.clear();
    console.log(chalk.green('Configuration reset to defaults.'));
  });
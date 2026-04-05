import { Command } from 'commander';
import chalk from 'chalk';

// Package versions (all synchronized at 0.2.0)
const VERSIONS = {
  cli: '0.2.0',
  core: '0.2.0',
  database: '0.2.0',
  queue: '0.2.0',
  shared: '0.2.0',
};

export const versionCommand = new Command('version')
  .description('Display version information')
  .option('--verbose', 'Show detailed version information')
  .option('--json', 'Output as JSON')
  .action((options) => {
    if (options.json) {
      console.log(JSON.stringify(VERSIONS, null, 2));
      return;
    }

    const boxTop = '┌─────────────────────────────────────────────────────────────┐';
    const boxBottom = '└─────────────────────────────────────────────────────────────┘';

    console.log(chalk.cyan(boxTop));
    console.log(chalk.cyan('│') + ' '.repeat(7) + chalk.white.bold('GUARDIANT') + ' - Security Scanner for AI Code    ' + chalk.cyan('│'));
    console.log(chalk.cyan('│') + '─'.repeat(61) + chalk.cyan('│'));
    console.log(chalk.cyan('│') + '  ' + `Version: ${chalk.green(VERSIONS.cli)}`.padEnd(28) + `Core: ${chalk.green(VERSIONS.core)}`.padEnd(28) + chalk.cyan('│'));
    console.log(chalk.cyan('│') + '  ' + `Database: ${VERSIONS.database}`.padEnd(28) + `Queue: ${VERSIONS.queue}`.padEnd(28) + chalk.cyan('│'));
    console.log(chalk.cyan('│') + '  ' + `Shared: ${VERSIONS.shared}`.padEnd(28) + `Node: ≥20`.padEnd(28) + chalk.cyan('│'));
    console.log(chalk.cyan(boxBottom));

    if (options.verbose) {
      console.log('');
      console.log(chalk.yellow.bold('Security Agents:'));
      console.log(chalk.gray('─'.repeat(60)));

      const agents = [
        { name: 'Recon', status: '✅', desc: 'Discovery & tech stack mapping' },
        { name: 'BaaS', status: '✅', desc: 'Supabase/Firebase/Appwrite security' },
        { name: 'Secrets', status: '✅', desc: 'API keys & credential exposure' },
        { name: 'Auth', status: '✅', desc: 'IDOR, privilege escalation, auth bypass' },
        { name: 'Injection', status: '✅', desc: 'SQLi, XSS, command injection' },
        { name: 'Supply Chain', status: '✅', desc: 'Dependency vulnerabilities' },
        { name: 'Business Logic', status: '✅', desc: 'Logic flaws, abnormal flows' },
        { name: 'Race Condition', status: '✅', desc: 'TOCTOU, double-spend, concurrency' },
      ];

      for (const agent of agents) {
        console.log(`  ${chalk.green(agent.status)} ${chalk.cyan(agent.name.padEnd(14))} ${chalk.gray(agent.desc)}`);
      }

      console.log('');
      console.log(chalk.yellow.bold('Analysis Frameworks:'));
      console.log(chalk.gray('─'.repeat(60)));
      console.log(`  ${chalk.magenta('VCVF')}   - Vibe Code Vulnerability Fingerprint (AI pattern detection)`);
      console.log(`  ${chalk.magenta('CVC')}   - Compound Vulnerability Chain (multi-bug linking)`);
      console.log(`  ${chalk.magenta('TIEF')}   - Trust Inversion Exploit Framework (architectural flaws)`);

      console.log('');
      console.log(chalk.yellow.bold('LLM Providers:'));
      console.log(chalk.gray('─'.repeat(60)));
      console.log(`  ${chalk.blue('Anthropic')}   - Claude 3.5 Sonnet (Primary)`);
      console.log(`  ${chalk.blue('OpenRouter')}  - Multi-model aggregation (Backup)`);
      console.log(`  ${chalk.blue('Gemini')}     - Google Gemini 1.5 Pro (Backup)`);

      console.log('');
      console.log(chalk.yellow.bold('Report Formats:'));
      console.log(chalk.gray('─'.repeat(60)));
      console.log(`  ${chalk.white('Executive')}  - Risk summary for business stakeholders`);
      console.log(`  ${chalk.white('Developer')}  - Technical details with code examples`);
      console.log(`  ${chalk.white('Security')}   - PoC exploits, CVSS scores, chained attacks`);
      console.log(`  Output: ${chalk.green('JSON')}, ${chalk.green('Markdown')}, ${chalk.green('HTML')}`);

      console.log('');
      console.log(chalk.yellow.bold('License:'));
      console.log(chalk.gray('─'.repeat(60)));
      console.log('  MIT License - See LICENSE file for details');

      console.log('');
      console.log(chalk.yellow('Website:'), chalk.white('https://github.com/paarthbhatt/Guardiant'));
      console.log(chalk.yellow('Docs:'), chalk.white('https://github.com/paarthbhatt/Guardiant#-documentation'));
      console.log(chalk.yellow('Issues:'), chalk.white('https://github.com/paarthbhatt/Guardiant/issues'));
    } else {
      console.log('');
      console.log(chalk.gray('  Run with --verbose for detailed component versions and capabilities'));
      console.log(chalk.gray('  Run `guardiant scan --help` for usage instructions'));
      console.log('');
    }
  });
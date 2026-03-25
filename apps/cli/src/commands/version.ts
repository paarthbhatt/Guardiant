import { Command } from 'commander';
import chalk from 'chalk';

export const versionCommand = new Command('version')
  .description('Display version information')
  .option('--verbose', 'Show detailed version information')
  .action((options) => {
    console.log(chalk.bold('\nGuardiant - Agentic Security Platform'));
    console.log(chalk.gray('─'.repeat(50)));
    console.log(`Version: ${chalk.cyan('0.1.0')}`);

    if (options.verbose) {
      console.log('\nComponents:');
      console.log(`  CLI:        ${chalk.green('0.1.0')}`);
      console.log(`  Core:       ${chalk.green('0.1.0')}`);
      console.log(`  Database:   ${chalk.green('0.1.0')}`);
      console.log(`  Queue:      ${chalk.green('0.1.0')}`);
      console.log(`  Shared:     ${chalk.green('0.1.0')}`);

      console.log('\nAgents:');
      const agents = [
        { name: 'Recon', priority: 'Critical', description: 'Discovery & reconnaissance' },
        { name: 'BaaS', priority: 'Critical', description: 'BaaS security (Supabase/Firebase)' },
        { name: 'Secrets', priority: 'Critical', description: 'Secrets detection' },
        { name: 'Auth', priority: 'High', description: 'Authentication & authorization' },
        { name: 'Injection', priority: 'High', description: 'Injection testing' },
        { name: 'Supply Chain', priority: 'Medium', description: 'Dependency analysis' },
        { name: 'Business Logic', priority: 'Medium', description: 'Business logic flaws' },
        { name: 'Race Condition', priority: 'Low', description: 'Race condition testing' },
      ];

      for (const agent of agents) {
        console.log(`  ${chalk.cyan(agent.name.padEnd(15))} [${chalk.yellow(agent.priority.padEnd(8))}] ${agent.description}`);
      }

      console.log('\nAnalysis Frameworks:');
      console.log(`  ${chalk.magenta('CVC')}   - Compound Vulnerability Chain`);
      console.log(`  ${chalk.magenta('VCVF')}  - Vibe Code Vulnerability Fingerprint`);
      console.log(`  ${chalk.magenta('TIEF')}  - Trust Inversion Exploit Framework`);

      console.log('\nLLM Providers:');
      console.log(`  ${chalk.blue('Anthropic')}  - Claude (Primary)`);
      console.log(`  ${chalk.blue('OpenRouter')} - Multi-model (Backup)`);
      console.log(`  ${chalk.blue('Gemini')}    - Google Gemini (Backup)`);
    }

    console.log('');
  });
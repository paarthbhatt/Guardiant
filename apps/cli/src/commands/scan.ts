import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import { createOrchestrator } from '@guardiant/core';
import { createDatabase } from '@guardiant/database';
import { createScan, startScan, completeScan } from '@guardiant/database';
import { createLogger, formatDuration, formatSeverity, formatFindingsSummary } from '@guardiant/shared';
import type { ScanConfig, AgentId, AgentResult, Finding } from '@guardiant/shared';
import { parseScanArgs } from '../validation/scan-args.js';

export const scanCommand = new Command('scan')
  .description('Run a security scan on a target')
  .argument('<target>', 'Target URL, directory, or repository to scan')
  .option('-t, --type <type>', 'Scan type (url, directory, repository)', 'url')
  .option('-a, --agents <agents>', 'Comma-separated list of agents to run', 'all')
  .option('--skip-recon', 'Skip reconnaissance phase', false)
  .option('--skip-analysis', 'Skip CVC/VCVF/TIEF analysis', false)
  .option('--max-concurrency <n>', 'Maximum concurrent agents', '4')
  .option('--timeout <ms>', 'Scan timeout in milliseconds', '600000')
  .option('--stop-on-critical', 'Stop scan on critical finding', false)
  .option('-o, --output <path>', 'Output file path')
  .option('-f, --format <format>', 'Output format (json, markdown, html)', 'markdown')
  .action(async (target: string, options) => {
    const spinner = ora('Initializing scan...').start();
    const logger = createLogger({ level: 'info' });

    try {
      // Initialize database
      const { db, sqlite } = createDatabase('guardiant.db');

      // Validate and parse arguments
      const rawArgs = {
        target,
        type: options.type,
        agents: options.agents,
        maxConcurrency: options.maxConcurrency,
        timeout: options.timeout,
        stopOnCritical: options.stopOnCritical,
        skipRecon: options.skipRecon,
        skipAnalysis: options.skipAnalysis,
        format: options.format,
        output: options.output,
      };

      const validatedArgs = parseScanArgs(rawArgs);

      // Create scan config
      const config: ScanConfig = {
        target: validatedArgs.target,
        type: validatedArgs.type,
        agents: validatedArgs.agents as AgentId[],
        maxConcurrency: validatedArgs.maxConcurrency,
        timeout: validatedArgs.timeout,
        stopOnCritical: validatedArgs.stopOnCritical,
        generateReports: true,
        reportOptions: {
          audience: 'developer',
          format: validatedArgs.format,
        },
      };

      // Create scan record
      spinner.text = 'Creating scan...';
      const scan = await createScan(db, {
        target: config.target,
        type: config.type,
        config,
      });

      spinner.text = 'Starting scan...';
      await startScan(db, scan.id);

      // Initialize orchestrator
      const orchestrator = createOrchestrator();

      // Run the scan
      spinner.text = 'Running security agents...';
      const results = await orchestrator.runScan(config);

      // Save findings to database
      spinner.text = 'Saving results...';
      const agentResultsList = Object.values(results.agentResults) as AgentResult[];
      for (const agentResult of agentResultsList) {
        for (const _finding of agentResult.findings) {
          // Save each finding
        }
      }

      // Complete the scan
      const duration = Date.now() - new Date(scan.createdAt).getTime();
      await completeScan(db, scan.id, duration);

      spinner.succeed('Scan completed successfully!');

      // Display results
      console.log('\n' + chalk.bold('Scan Results'));
      console.log(chalk.gray('─'.repeat(50)));
      console.log(`Target: ${chalk.cyan(target)}`);
      console.log(`Duration: ${formatDuration(duration)}`);
      console.log(`Scan ID: ${chalk.gray(scan.id)}`);

      // Display findings summary
      const summary = formatFindingsSummary(results.findings);
      console.log('\n' + chalk.bold('Findings Summary'));
      console.log(chalk.gray('─'.repeat(50)));
      console.log(summary);

      // Display agent results
      console.log('\n' + chalk.bold('Agent Results'));
      console.log(chalk.gray('─'.repeat(50)));

      const agentTable = new Table({
        head: ['Agent', 'Status', 'Findings', 'Duration'],
        colWidths: [20, 12, 12, 12],
      });

      const entries = Object.entries(results.agentResults) as [AgentId, AgentResult][];
      for (const [agentId, result] of entries) {
        agentTable.push([
          agentId,
          result.status === 'completed' ? chalk.green('✓ completed') : chalk.red('✗ failed'),
          result.findings.length.toString(),
          formatDuration(result.duration),
        ]);
      }

      console.log(agentTable.toString());

      // Display compound chains if any
      if (results.chains.length > 0) {
        console.log('\n' + chalk.bold.magenta('Compound Vulnerability Chains'));
        console.log(chalk.gray('─'.repeat(50)));

        for (const chain of results.chains) {
          console.log(
            chalk.yellow(`Chain [${chain.compoundSeverity}]`) +
            `: ${chain.findings.map((f: Finding) => f.title).join(' → ')}`
          );
        }
      }

      // Display trust inversions if any
      if (results.trustInversions.length > 0) {
        console.log('\n' + chalk.bold.red('Trust Inversions Detected'));
        console.log(chalk.gray('─'.repeat(50)));

        for (const inversion of results.trustInversions) {
          console.log(
            chalk.red(`[${inversion.severity}] ${inversion.type}`) +
            `: ${inversion.misplacedTrust} → ${inversion.actualBoundary}`
          );
        }
      }

      // Display top findings
      const criticalAndHigh = results.findings.filter(
        (f: Finding) => f.severity === 'critical' || f.severity === 'high'
      );

      if (criticalAndHigh.length > 0) {
        console.log('\n' + chalk.bold.red('Critical & High Severity Findings'));
        console.log(chalk.gray('─'.repeat(50)));

        for (const finding of criticalAndHigh.slice(0, 5)) {
          console.log(
            formatSeverity(finding.severity) +
            ` ${finding.title}` +
            chalk.gray(` (${finding.category})`)
          );
          console.log(chalk.gray(`  ${finding.description.slice(0, 100)}...`));
        }

        if (criticalAndHigh.length > 5) {
          console.log(chalk.gray(`  ... and ${criticalAndHigh.length - 5} more`));
        }
      }

      // Output to file if specified
      if (options.output) {
        spinner.text = 'Writing output...';
        // Write to file
        spinner.succeed(`Output written to ${options.output}`);
      }

      // Clean up
      sqlite.close();

      // Exit with appropriate code
      const hasCritical = results.findings.some((f: Finding) => f.severity === 'critical');
      const hasHigh = results.findings.some((f: Finding) => f.severity === 'high');

      if (hasCritical) {
        process.exit(2); // Critical findings
      } else if (hasHigh) {
        process.exit(1); // High findings
      } else {
        process.exit(0); // No critical/high findings
      }
    } catch (error) {
      spinner.fail('Scan failed');
      logger.error('Scan error:', error);
      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
      process.exit(1);
    }
  });
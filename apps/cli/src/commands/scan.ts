import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import { existsSync, writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { createOrchestrator, registerDefaultAgents } from '@guardiant/core';
import { createDatabase } from '@guardiant/database';
import { createScan, startScan, completeScan } from '@guardiant/database';
import { createLogger, formatDuration, formatSeverity, formatFindingsSummary, Analytics } from '@guardiant/shared';
import type { ScanConfig, AgentId, AgentResult, Finding } from '@guardiant/shared';
import { parseScanArgs } from '../validation/scan-args.js';

import { formatAsSarif } from '@guardiant/core';

// Generate a simple scan ID if database is unavailable
function generateScanId(): string {
  return `scan-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

function generateReport(
  results: { findings: Finding[]; chains: unknown[]; trustInversions: unknown[]; agentResults: Record<AgentId, AgentResult>; exploitNarratives?: Array<{ findingId: string; attackSteps: string[]; pocCommand: string; whyItWorks: string; trustBoundary: string; fix: string; severity: string }>; fixPatches?: Array<{ findingId: string; filePath: string; description: string; diff: string; confidence: number; autoApplicable: boolean; reasoning: string }> },
  target: string,
  durationMs: number,
  scanId: string,
  format: string
): string {
  if (format === 'sarif') {
    return formatAsSarif({
      id: scanId,
      scanId,
      target,
      timestamp: new Date().toISOString(),
      duration: durationMs,
      findings: results.findings,
      chains: results.chains as any,
      trustInversions: results.trustInversions as any,
      agentResults: results.agentResults,
      vcvfFingerprints: [],
    });
  }

  if (format === 'json') {
    return JSON.stringify({
      scanId,
      target,
      duration: durationMs,
      findings: results.findings,
      chains: results.chains,
      trustInversions: results.trustInversions,
      exploitNarratives: results.exploitNarratives ?? [],
      fixPatches: results.fixPatches ?? [],
      agentResults: Object.fromEntries(
        Object.entries(results.agentResults).map(([id, r]) => [id, { status: r.status, findings: r.findings.length, duration: r.duration }])
      ),
    }, null, 2);
  }

  // Markdown format
  const lines: string[] = [];
  lines.push(`# Guardiant Scan Report`);
  lines.push('');
  lines.push(`- **Target:** ${target}`);
  lines.push(`- **Scan ID:** ${scanId}`);
  lines.push(`- **Duration:** ${formatDuration(durationMs)}`);
  lines.push(`- **Findings:** ${results.findings.length}`);
  lines.push('');

  // Summary
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of results.findings) {
    const sev = f.severity as keyof typeof counts;
    if (sev in counts) counts[sev]++;
  }
  lines.push(`## Summary`);
  lines.push('');
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${counts.critical} |`);
  lines.push(`| High | ${counts.high} |`);
  lines.push(`| Medium | ${counts.medium} |`);
  lines.push(`| Low | ${counts.low} |`);
  lines.push('');

  // Trust inversions
  if (results.trustInversions.length > 0) {
    lines.push(`## Trust Inversions`);
    lines.push('');
    for (const inv of results.trustInversions as Array<{ severity: string; type: string; misplacedTrust: string; actualBoundary: string }>) {
      lines.push(`- **[${inv.severity}] ${inv.type}:** ${inv.misplacedTrust} → ${inv.actualBoundary}`);
    }
    lines.push('');
  }

  // Findings
  if (results.findings.length > 0) {
    lines.push(`## Findings`);
    lines.push('');
    for (const f of results.findings) {
      lines.push(`### ${f.severity.toUpperCase()}: ${f.title}`);
      lines.push('');
      lines.push(`- **Category:** ${f.category}`);
      lines.push(`- **CVSS:** ${f.cvssScore}`);
      lines.push(`- **Confidence:** ${f.confidence}`);
      lines.push(`- **Description:** ${f.description}`);
      if (f.remediation) {
        lines.push(`- **Remediation:** ${f.remediation.summary}`);
      }
      lines.push('');
    }
  }

  // Exploit Narratives
  const narratives = results.exploitNarratives ?? [];
  if (narratives.length > 0) {
    lines.push(`## Exploit Narratives (${narratives.length})`);
    lines.push('');
    for (const n of narratives) {
      lines.push(`### [${n.severity.toUpperCase()}] ${n.findingId}`);
      lines.push('');
      lines.push(`**Attack Steps:**`);
      for (const step of n.attackSteps) {
        lines.push(`- ${step}`);
      }
      lines.push('');
      lines.push(`**PoC:**`);
      lines.push('```');
      lines.push(n.pocCommand);
      lines.push('```');
      lines.push('');
      lines.push(`**Why It Works:** ${n.whyItWorks}`);
      lines.push('');
      lines.push(`**Trust Boundary:** ${n.trustBoundary}`);
      lines.push('');
      lines.push(`**Fix:**`);
      lines.push('```');
      lines.push(n.fix);
      lines.push('```');
      lines.push('');
    }
  }

  // Fix Patches
  const patches = results.fixPatches ?? [];
  if (patches.length > 0) {
    lines.push(`## Fix Patches (${patches.length})`);
    lines.push('');
    for (const p of patches) {
      lines.push(`### ${p.findingId} → ${p.filePath}`);
      lines.push('');
      lines.push(`- **Description:** ${p.description}`);
      lines.push(`- **Confidence:** ${(p.confidence * 100).toFixed(0)}%`);
      lines.push(`- **Auto-applicable:** ${p.autoApplicable ? 'Yes' : 'No'}`);
      lines.push(`- **Reasoning:** ${p.reasoning}`);
      lines.push('');
      lines.push(`**Diff:**`);
      lines.push('```diff');
      lines.push(p.diff);
      lines.push('```');
      lines.push('');
    }
  }

  return lines.join('\n');
}

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
  .option('-f, --format <format>', 'Output format (json, markdown, html, sarif)', 'markdown')
  .option('--incremental', 'Run incremental scan based on git diff', false)
  .option('--base-ref <ref>', 'Base git reference for incremental scan', 'HEAD~1')
  .action(async (target: string, options) => {
    const spinner = ora('Initializing scan...').start();
    const logger = createLogger({ level: 'info' });

    try {
      // Validate and parse arguments first
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
        incremental: options.incremental,
        baseRef: options.baseRef,
      };

      const validatedArgs = parseScanArgs(rawArgs);

      // Auto-detect scan type if still 'url' and target is a local path
      let scanType = validatedArgs.type;
      if (scanType === 'url') {
        const targetStr = validatedArgs.target;
        // Check for Windows drive letter paths (e.g., C:\Users\...)
        const isWindowsPath = /^[a-zA-Z]:[\\/]/.test(targetStr);
        if (isWindowsPath) {
          if (existsSync(targetStr)) {
            scanType = 'directory';
          }
        } else {
          try {
            const url = new URL(targetStr);
            // Check it's actually an HTTP/HTTPS URL, not some other protocol
            if (url.protocol !== 'http:' && url.protocol !== 'https:') {
              if (existsSync(targetStr)) {
                scanType = 'directory';
              }
            }
          } catch {
            // Not a valid URL - check if it's a local path
            if (existsSync(targetStr)) {
              scanType = 'directory';
            }
          }
        }
      }

      logger.info(`Scan type detected: ${scanType}`);

      // Create scan config
      const config: ScanConfig = {
        target: validatedArgs.target,
        type: scanType,
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

      // Initialize database (optional - may fail on Windows without build tools)
      let db: any = null;
      let sqlite: any = null;
      let scanId: string;
      let dbAvailable = true;

      try {
        const dbResult = await createDatabase('guardiant.db');
        db = dbResult.db;
        sqlite = dbResult.sqlite;
        
        const scan = await createScan(db, {
          target: config.target,
          type: config.type,
          config,
        });
        scanId = scan.id;
        
        await startScan(db, scanId);
      } catch (dbError) {
        // Database unavailable - continue without persistence
        dbAvailable = false;
        scanId = generateScanId();
        console.warn(chalk.yellow('⚠️  Database unavailable (likely missing build tools on Windows).'));
        console.warn(chalk.yellow('   Scan will proceed without persistence.'));
        console.warn(chalk.yellow('   Install Visual Studio Build Tools for full functionality.\n'));
      }

      // Track scan start
      Analytics.trackScanStarted({
        target: config.target,
        agents: config.agents || [],
      });

      // Register all default agents before running scan
      registerDefaultAgents();

      const orchestrator = createOrchestrator();
      const startTime = Date.now();

      // Run the scan
      spinner.text = 'Running security agents...';
      const results = await orchestrator.runScan(config);

      // Calculate duration
      const durationMs = Date.now() - startTime;

      // Save findings to database (if available)
      if (dbAvailable && db) {
        spinner.text = 'Saving results...';
        const agentResultsList = Object.values(results.agentResults) as AgentResult[];
        for (const agentResult of agentResultsList) {
          for (const _finding of agentResult.findings) {
            // TODO: Implement finding persistence
          }
        }

        // Complete the scan
        await completeScan(db, scanId, durationMs);
      } else {
        spinner.text = 'Processing results...';
      }

      // Track scan completion
      const severityCounts = results.findings.reduce(
        (acc, f) => {
          const severity = f.severity as 'critical' | 'high' | 'medium' | 'low';
          if (acc[severity] !== undefined) {
            acc[severity]++;
          }
          return acc;
        },
        { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>
      );

      Analytics.trackScanCompleted({
        target: config.target,
        agents: config.agents || [],
        findingsCount: results.findings.length,
        duration: Math.floor(durationMs / 1000),
        criticalCount: severityCounts.critical,
        highCount: severityCounts.high,
        mediumCount: severityCounts.medium,
        lowCount: severityCounts.low,
      });

      spinner.succeed('Scan completed successfully!');

      // Display results
      console.log('\n' + chalk.bold('Scan Results'));
      console.log(chalk.gray('─'.repeat(50)));
      console.log(`Target: ${chalk.cyan(target)}`);
      console.log(`Duration: ${formatDuration(durationMs)}`);
      console.log(`Scan ID: ${chalk.gray(scanId)}`);

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
        try {
          const outputDir = dirname(options.output);
          if (!existsSync(outputDir)) {
            mkdirSync(outputDir, { recursive: true });
          }

          const reportContent = generateReport(results, target, durationMs, scanId, options.format);
          writeFileSync(options.output, reportContent, 'utf-8');
          spinner.succeed(`Output written to ${options.output}`);
        } catch (writeError) {
          spinner.fail(`Failed to write output: ${writeError instanceof Error ? writeError.message : 'Unknown error'}`);
        }
      }

      // Clean up
      if (sqlite) {
        sqlite.close();
      }

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
      
      // Track error
      Analytics.trackScanError({
        target,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
      process.exit(1);
    }
  });

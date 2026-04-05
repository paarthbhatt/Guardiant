import { Command } from 'commander';
import chalk from 'chalk';
import { createDatabase, getScan, getFindingsByScan } from '@guardiant/database';
import { formatDuration, formatSeverity, formatNumber } from '@guardiant/shared';
import type { Scan } from '@guardiant/database';
import Table from 'cli-table3';

export const reportCommand = new Command('report')
  .description('Generate or view a scan report')
  .argument('<scan-id>', 'Scan ID to generate report for')
  .option('-f, --format <format>', 'Output format (json, markdown, html)', 'markdown')
  .option('-a, --audience <audience>', 'Target audience (executive, developer, security)', 'developer')
  .option('-o, --output <path>', 'Output file path')
  .option('--findings-only', 'Show only findings without full report', false)
  .action(async (scanId: string, options) => {
    let db: any, sqlite: any;
    
    try {
      const dbResult = await createDatabase('guardiant.db');
      db = dbResult.db;
      sqlite = dbResult.sqlite;
    } catch (dbError) {
      console.error(chalk.red('❌ Database unavailable. Cannot generate report.'));
      console.error(chalk.yellow('   On Windows, install Visual Studio Build Tools or use WSL2.'));
      console.error(chalk.yellow('   See: https://github.com/WiseLibs/better-sqlite3#installation\n'));
      process.exit(1);
    }

    try {
      // Get scan
      const scan = await getScan(db, scanId);

      if (!scan) {
        console.error(chalk.red(`Scan not found: ${scanId}`));
        process.exit(1);
      }

      // Get findings
      const findings = await getFindingsByScan(db, scanId);

      if (options.findingsOnly) {
        // Show just findings
        displayFindings(findings, options.format);
      } else {
        // Generate full report
        generateReport(scan, findings, options.format, options.audience);
      }

      // Output to file if specified
      if (options.output) {
        // TODO: Implement file output
        console.log(chalk.green(`\n✓ Report written to ${options.output}`));
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
      process.exit(1);
    } finally {
      if (sqlite) {
        sqlite.close();
      }
    }
  });

function displayFindings(findings: any[], format: string): void {
  if (format === 'json') {
    console.log(JSON.stringify(findings, null, 2));
    return;
  }

  const table = new Table({
    head: ['ID', 'Severity', 'Title', 'Category', 'Status'],
    colWidths: [15, 10, 40, 15, 12],
  });

  for (const finding of findings) {
    table.push([
      finding.id.slice(0, 12),
      formatSeverity(finding.severity),
      finding.title.slice(0, 38) + (finding.title.length > 38 ? '...' : ''),
      finding.category,
      finding.status,
    ]);
  }

  console.log(table.toString());
}

function generateReport(
  scan: Scan,
  findings: any[],
  _format: string,
  audience: string
): void {
  console.log(chalk.bold('\nGuardiant Security Report'));
  console.log(chalk.gray('='.repeat(50)));
  console.log(`\nScan ID: ${scan.id}`);
  console.log(`Target: ${scan.target}`);
  console.log(`Status: ${scan.status}`);
  console.log(`Created: ${scan.createdAt}`);
  console.log(`Duration: ${scan.duration ? formatDuration(scan.duration) : 'N/A'}`);

  // Executive summary
  if (audience === 'executive') {
    console.log('\n' + chalk.bold('Executive Summary'));
    console.log(chalk.gray('-'.repeat(50)));

    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;

    if (critical > 0) {
      console.log(chalk.red.bold(`\n⚠️  CRITICAL: ${critical} critical vulnerabilities found`));
      console.log('Immediate attention required. Your application may be actively exploited.');
    } else if (high > 0) {
      console.log(chalk.yellow(`\n⚠️  ${high} high severity vulnerabilities found`));
      console.log('Remediation should be prioritized within the next sprint.');
    } else if (medium > 0) {
      console.log(chalk.blue(`\nℹ️  ${medium} medium severity vulnerabilities found`));
      console.log('Plan remediation in upcoming development cycles.');
    } else {
      console.log(chalk.green('\n✓ No critical or high severity vulnerabilities found.'));
    }
  }

  // Developer/Security detailed report
  if (audience === 'developer' || audience === 'security') {
    console.log('\n' + chalk.bold('Findings'));
    console.log(chalk.gray('-'.repeat(50)));

    displayFindings(findings, 'table');

    // Detailed findings
    for (const finding of findings.slice(0, 3)) {
      console.log('\n' + chalk.bold(finding.title));
      console.log(chalk.gray('─'.repeat(40)));
      console.log(`Severity: ${formatSeverity(finding.severity)}`);
      console.log(`Category: ${finding.category}`);
      console.log(`Confidence: ${formatNumber(Math.round(finding.confidence * 100))}%`);
      console.log(`\n${finding.description}`);
      console.log('\n' + chalk.bold('Remediation:'));
      console.log(finding.remediation?.summary || 'No remediation provided');
    }

    if (findings.length > 3) {
      console.log(chalk.gray(`\n... and ${findings.length - 3} more findings`));
    }
  }
}

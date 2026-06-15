import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { existsSync, writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { createOrchestrator, registerDefaultAgents } from '@guardiant/core';
import { createLogger, formatDuration, type FixPatch } from '@guardiant/shared';
import { parseFixArgs } from '../validation/agent-args.js';

function generateFixReport(
  patches: FixPatch[],
  applied: string[],
  skipped: string[],
  target: string,
  durationMs: number
): string {
  const lines: string[] = [];
  lines.push(`# Guardiant Fix Report`);
  lines.push('');
  lines.push(`- **Target:** ${target}`);
  lines.push(`- **Patches proposed:** ${patches.length}`);
  lines.push(`- **Applied:** ${applied.length}`);
  lines.push(`- **Skipped:** ${skipped.length}`);
  lines.push(`- **Duration:** ${formatDuration(durationMs)}`);
  lines.push('');

  if (patches.length === 0) {
    lines.push('No patches generated.');
    return lines.join('\n');
  }

  for (const patch of patches) {
    lines.push(`## ${patch.findingId} → ${patch.filePath}`);
    lines.push('');
    lines.push(`**Description:** ${patch.description}`);
    lines.push(`**Confidence:** ${(patch.confidence * 100).toFixed(0)}%`);
    lines.push(`**Auto-applicable:** ${patch.autoApplicable ? 'Yes' : 'No'}`);
    lines.push(`**Status:** ${applied.includes(patch.findingId) ? 'APPLIED' : 'PROPOSED'}`);
    lines.push('');
    lines.push('**Reasoning:** ' + patch.reasoning);
    lines.push('');
    lines.push('### Diff');
    lines.push('```diff');
    lines.push(patch.diff);
    lines.push('```');
    lines.push('');
  }

  return lines.join('\n');
}

export const fixCommand = new Command('fix')
  .description('Generate and (optionally) apply fix patches for findings')
  .argument('[target]', 'Target directory to scan and fix')
  .option('-t, --type <type>', 'Scan type (directory, repository)', 'directory')
  .option('--scan-id <id>', 'Re-fix from a saved scan ID')
  .option('--apply', 'Apply patches to disk and create a git commit per fix', false)
  .option('--interactive', 'Prompt per finding (requires TTY)', false)
  .option('--min-confidence <n>', 'Minimum confidence for auto-apply (0-1)', '0.7')
  .option('-f, --format <format>', 'Output format (json, markdown, html)', 'markdown')
  .option('-o, --output <path>', 'Write report to file')
  .action(async (targetArg: string | undefined, options) => {
    const spinner = ora('Preparing fix run...').start();
    const logger = createLogger({ level: 'info' });

    try {
      const rawArgs = {
        target: targetArg,
        scanId: options.scanId,
        apply: options.apply === true,
        interactive: options.interactive === true,
        minConfidence: options.minConfidence,
        format: options.format,
        output: options.output,
      };
      const args = parseFixArgs(rawArgs);

      if (!args.target && !args.scanId) {
        spinner.fail('Either a target directory or --scan-id is required');
        process.exit(1);
      }

      if (args.target && !existsSync(args.target)) {
        spinner.fail(`Target directory does not exist: ${args.target}`);
        process.exit(1);
      }

      registerDefaultAgents();
      const orchestrator = createOrchestrator();
      const startTime = Date.now();

      const target = args.target ?? '<historical-scan>';
      const mode: 'dry-run' | 'apply' | 'interactive' = args.apply
        ? 'apply'
        : args.interactive
          ? 'interactive'
          : 'dry-run';

      spinner.text = `Running scan + fix agent (${mode}) against ${target}...`;

      const result = args.target
        ? await orchestrator.runScan({
            target: args.target,
            type: args.type,
            autoFix: args.apply,
            phases: { exploit: false, fix: true },
          })
        : { fixPatches: [] as FixPatch[] };

      const durationMs = Date.now() - startTime;
      const patches = result.fixPatches;

      spinner.succeed(`Fix agent proposed ${patches.length} patch(es) in ${formatDuration(durationMs)}`);

      // Display
      console.log('\n' + chalk.bold('Fix Patches'));
      console.log(chalk.gray('─'.repeat(60)));

      if (patches.length === 0) {
        console.log(chalk.gray('No patches could be generated for the findings.'));
        console.log(chalk.gray('Architectural findings (A04_INSECURE_DESIGN) and findings without a code example are skipped.'));
      }

      for (const patch of patches.slice(0, 20)) {
        const conf = patch.confidence >= args.minConfidence ? chalk.green : chalk.yellow;
        console.log(
          conf(`[${(patch.confidence * 100).toFixed(0)}%]`) +
          ` ${patch.findingId} → ${chalk.cyan(patch.filePath)}`
        );
        console.log(chalk.gray(`  ${patch.description}`));
        if (patch.autoApplicable && args.apply) {
          console.log(chalk.green('  ✓ Applied'));
        } else {
          console.log(chalk.gray('  (proposed — run with --apply to commit)'));
        }
        console.log('');
      }

      if (patches.length > 20) {
        console.log(chalk.gray(`... and ${patches.length - 20} more`));
      }

      if (args.apply) {
        const applied = patches.filter(p => p.autoApplicable && p.confidence >= args.minConfidence);
        console.log(chalk.green(`\n✓ Applied ${applied.length} patch(es)`));
        if (applied.length > 0) {
          console.log(chalk.gray('Each applied patch was committed to git individually (if a repo was detected).'));
        }
      } else {
        console.log(chalk.gray('\nDry-run: nothing was changed on disk. Use --apply to commit.'));
      }

      // Output to file if specified
      if (args.output) {
        const outputDir = dirname(args.output);
        if (!existsSync(outputDir)) {
          mkdirSync(outputDir, { recursive: true });
        }
        const applied = patches
          .filter(p => p.autoApplicable && p.confidence >= args.minConfidence && args.apply)
          .map(p => p.findingId);
        const skipped = patches
          .filter(p => !(p.autoApplicable && p.confidence >= args.minConfidence && args.apply))
          .map(p => p.findingId);
        const content = args.format === 'json'
          ? JSON.stringify({ target, mode, patches, applied, skipped }, null, 2)
          : generateFixReport(patches, applied, skipped, target, durationMs);
        writeFileSync(args.output, content, 'utf-8');
        console.log(chalk.green(`\n✓ Report written to ${args.output}`));
      }

      process.exit(0);
    } catch (error) {
      spinner.fail('Fix run failed');
      logger.error('Fix error:', error);
      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
      process.exit(1);
    }
  });

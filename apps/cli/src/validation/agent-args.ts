import { z } from 'zod';

/**
 * Zod schema for the `guardiant exploit` CLI arguments
 */
export const ExploitArgSchema = z.object({
  /** Optional: target URL/directory. If omitted, --scan-id is required */
  target: z.string().min(1).optional(),

  /** Optional: scan ID to re-exploit from a saved scan */
  scanId: z.string().optional(),

  /** Optional: scan type */
  type: z
    .enum(['url', 'directory', 'repository'])
    .default('url'),

  /** Run active PoCs against the target */
  active: z.boolean().default(false),

  /** Filter by severity (lowest to include) */
  minSeverity: z
    .enum(['info', 'low', 'medium', 'high', 'critical'])
    .default('low'),

  /** Output format */
  format: z
    .enum(['json', 'markdown', 'html'])
    .default('markdown'),

  /** Optional output file */
  output: z.string().optional(),
});

export type ExploitArgs = z.infer<typeof ExploitArgSchema>;

export function parseExploitArgs(rawArgs: Record<string, unknown>): ExploitArgs {
  const result = ExploitArgSchema.safeParse(rawArgs);
  if (!result.success) {
    const issues = result.error.issues
      .map((i: { path: (string | number)[]; message: string }) => `  • ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid exploit arguments:\n${issues}`);
  }
  return result.data;
}

/**
 * Zod schema for the `guardiant fix` CLI arguments
 */
export const FixArgSchema = z.object({
  /** Optional: target directory. If omitted, --scan-id is required */
  target: z.string().min(1).optional(),

  /** Optional: scan ID to re-fix from a saved scan */
  scanId: z.string().optional(),

  /** Optional: scan type */
  type: z
    .enum(['directory', 'repository'])
    .default('directory'),

  /** Apply patches to disk */
  apply: z.boolean().default(false),

  /** Prompt per finding */
  interactive: z.boolean().default(false),

  /** Minimum confidence for auto-apply (0-1) */
  minConfidence: z
    .string()
    .default('0.7')
    .transform(Number)
    .pipe(z.number().min(0).max(1)),

  /** Output format */
  format: z
    .enum(['json', 'markdown', 'html'])
    .default('markdown'),

  /** Optional output file */
  output: z.string().optional(),
});

export type FixArgs = z.infer<typeof FixArgSchema>;

export function parseFixArgs(rawArgs: Record<string, unknown>): FixArgs {
  const result = FixArgSchema.safeParse(rawArgs);
  if (!result.success) {
    const issues = result.error.issues
      .map((i: { path: (string | number)[]; message: string }) => `  • ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid fix arguments:\n${issues}`);
  }
  return result.data;
}

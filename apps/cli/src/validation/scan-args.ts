import { z } from 'zod';

/**
 * Zod schema for the `guardiant scan` CLI arguments
 */
export const ScanArgSchema = z.object({
  /** Target URL, directory, or repository */
  target: z
    .string()
    .min(1, 'Target cannot be empty')
    .refine((v) => {
      // Accept URLs or file-system paths (relative or absolute)
      try {
        new URL(v);
        return true;
      } catch {
        // Allow relative/absolute paths too
        return v.length > 0;
      }
    }, 'Target must be a valid URL or file path'),

  type: z
    .enum(['url', 'directory', 'repository'])
    .default('url'),

  agents: z
    .string()
    .default('all')
    .transform((v) => v.split(',').map((s) => s.trim()))
    .pipe(
      z.array(
        z.enum(['all', 'recon', 'baas', 'secrets', 'auth', 'injection', 'supply_chain', 'business_logic', 'race_condition'])
      )
    ),

  maxConcurrency: z
    .string()
    .default('4')
    .transform(Number)
    .pipe(z.number().int().min(1).max(10)),

  timeout: z
    .string()
    .default('600000')
    .transform(Number)
    .pipe(z.number().int().min(1000).max(7200000)),

  format: z
    .enum(['json', 'markdown', 'html'])
    .default('markdown'),

  output: z.string().optional(),
  stopOnCritical: z.boolean().default(false),
  skipRecon: z.boolean().default(false),
  skipAnalysis: z.boolean().default(false),
});

export type ScanArgs = z.infer<typeof ScanArgSchema>;

/**
 * Parse and validate scan arguments, returning a typed result or throwing
 * a user-friendly error message on validation failure.
 */
export function parseScanArgs(rawArgs: Record<string, unknown>): ScanArgs {
  const result = ScanArgSchema.safeParse(rawArgs);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid scan arguments:\n${issues}`);
  }
  return result.data;
}

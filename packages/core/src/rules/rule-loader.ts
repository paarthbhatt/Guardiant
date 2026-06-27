import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { z } from 'zod';
import * as yaml from 'js-yaml';
import type { VCVFPatternDefinition, CodePattern, AstPattern, VCVFPredictedVulnerability } from '@guardiant/shared';
import { VCVF_PATTERNS } from '@guardiant/shared';
import { createLogger } from '@guardiant/shared';

const logger = createLogger({ level: 'info' });

// ─── Zod Schemas ────────────────────────────────────────────────────

const CodePatternSchema = z.object({
  pattern: z.string(),
  description: z.string(),
  weight: z.number().min(0).max(1),
  is_vulnerability: z.boolean().default(false),
});

const PredictedVulnSchema = z.object({
  type: z.string(),
  probability: z.number().min(0).max(1),
  owasp: z.string(),
  reason: z.string(),
});

const AstPatternSchema = z.object({
  node_type: z.string(),
  method_names: z.array(z.string()).optional(),
  object_names: z.array(z.string()).optional(),
  description: z.string(),
  weight: z.number().min(0).max(1),
  is_vulnerability: z.boolean().default(false),
});

const VCVFRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  enabled: z.boolean().default(true),
  confidence: z.number().min(0).max(1),
  file_patterns: z.array(z.string()).default([]),
  exclude_patterns: z.array(z.string()).default([]),
  code_patterns: z.array(CodePatternSchema),
  ast_patterns: z.array(AstPatternSchema).optional(),
  negative_suppressors: z.array(z.string()).default([]),
  min_patterns_required: z.number().min(1).optional(),
  predicted_vulnerabilities: z.array(PredictedVulnSchema),
});

const SecretRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  enabled: z.boolean().default(true),
  file_patterns: z.array(z.string()).default([]),
  exclude_patterns: z.array(z.string()).default([]),
  patterns: z.array(z.object({
    pattern: z.string(),
    name: z.string(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    confidence: z.number().min(0).max(1).default(0.85),
  })),
  negative_suppressors: z.array(z.string()).default([]),
});

export type VCVFRuleConfig = z.infer<typeof VCVFRuleSchema>;
export type SecretRuleConfig = z.infer<typeof SecretRuleSchema>;

// ─── Rule Loader ────────────────────────────────────────────────────

export class RuleLoader {
  private rulesDir: string;

  constructor(rulesDir?: string) {
    // Default: packages/core/rules relative to the package root
    this.rulesDir = rulesDir ?? join(
      new URL('.', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), // Windows fix
      '..', '..', 'rules'
    );
  }

  /**
   * Load all VCVF rules from YAML files.
   * Falls back to hardcoded VCVF_PATTERNS if no YAML files found.
   */
  async loadVCVFRules(): Promise<VCVFPatternDefinition[]> {
    const yamlDir = join(this.rulesDir, 'vcvf');
    if (!existsSync(yamlDir)) {
      logger.warn(`VCVF rules directory not found: ${yamlDir}, using defaults`);
      return VCVF_PATTERNS;
    }

    const files = readdirSync(yamlDir).filter(f => extname(f) === '.yaml' || extname(f) === '.yml');
    if (files.length === 0) {
      logger.warn('No VCVF YAML rules found, using defaults');
      return VCVF_PATTERNS;
    }

    const patterns: VCVFPatternDefinition[] = [];

    for (const file of files) {
      try {
        const content = readFileSync(join(yamlDir, file), 'utf-8');
        const raw = yaml.load(content) as Record<string, unknown>;
        const parsed = VCVFRuleSchema.safeParse(raw);

        if (!parsed.success) {
          logger.warn(`Invalid VCVF rule in ${file}: ${parsed.error.message}`);
          continue;
        }

        const rule = parsed.data;
        if (!rule.enabled) continue;

        patterns.push(this.yamlToVCVFDefinition(rule));
        logger.info(`Loaded VCVF rule: ${rule.id} from ${file}`);
      } catch (err) {
        logger.warn(`Failed to load ${file}: ${err}`);
      }
    }

    // If YAML produced no valid rules, fall back to defaults
    if (patterns.length === 0) {
      logger.warn('No valid VCVF rules loaded from YAML, using defaults');
      return VCVF_PATTERNS;
    }

    // Merge: YAML rules override defaults, defaults fill gaps
    const yamlIds = new Set(patterns.map(p => p.type));
    for (const defaultPattern of VCVF_PATTERNS) {
      if (!yamlIds.has(defaultPattern.type)) {
        patterns.push(defaultPattern);
      }
    }

    return patterns;
  }

  /**
   * Load all secret detection rules from YAML files.
   * Returns merged pattern list for the Secrets agent.
   */
  async loadSecretRules(): Promise<Array<{
    pattern: RegExp;
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: number;
    negativeSuppressors: string[];
  }>> {
    const yamlDir = join(this.rulesDir, 'secrets');
    if (!existsSync(yamlDir)) {
      logger.warn(`Secrets rules directory not found: ${yamlDir}`);
      return [];
    }

    const files = readdirSync(yamlDir).filter(f => extname(f) === '.yaml' || extname(f) === '.yml');
    const patterns: Array<{
      pattern: RegExp;
      name: string;
      severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
      confidence: number;
      negativeSuppressors: string[];
    }> = [];

    for (const file of files) {
      try {
        const content = readFileSync(join(yamlDir, file), 'utf-8');
        const raw = yaml.load(content) as Record<string, unknown>;
        const parsed = SecretRuleSchema.safeParse(raw);

        if (!parsed.success) {
          logger.warn(`Invalid secret rule in ${file}: ${parsed.error.message}`);
          continue;
        }

        const rule = parsed.data;
        if (!rule.enabled) continue;

        for (const p of rule.patterns) {
          patterns.push({
            pattern: new RegExp(p.pattern, 'gi'),
            name: p.name,
            severity: p.severity,
            confidence: p.confidence,
            negativeSuppressors: rule.negative_suppressors,
          });
        }

        logger.info(`Loaded secret rule: ${rule.id} (${rule.patterns.length} patterns) from ${file}`);
      } catch (err) {
        logger.warn(`Failed to load ${file}: ${err}`);
      }
    }

    return patterns;
  }

  /**
   * Convert a parsed YAML rule into a VCVFPatternDefinition.
   */
  private yamlToVCVFDefinition(rule: VCVFRuleConfig): VCVFPatternDefinition {
    const codePatterns: CodePattern[] = rule.code_patterns.map(cp => ({
      pattern: new RegExp(cp.pattern, 'gi'),
      description: cp.description,
      weight: cp.weight,
      isVulnerability: cp.is_vulnerability,
    }));

    const predictedVulnerabilities: VCVFPredictedVulnerability[] = rule.predicted_vulnerabilities.map(pv => ({
      type: pv.type,
      probability: pv.probability,
      reason: pv.reason,
      owaspCategory: pv.owasp,
    }));

    const astPatterns: AstPattern[] | undefined = rule.ast_patterns?.map(ap => ({
      nodeType: ap.node_type,
      methodNames: ap.method_names,
      objectNames: ap.object_names,
      description: ap.description,
      weight: ap.weight,
      isVulnerability: ap.is_vulnerability,
    }));

    return {
      type: rule.id as VCVFPatternDefinition['type'],
      name: rule.name,
      description: rule.description,
      confidence: rule.confidence,
      filePatterns: rule.file_patterns,
      codePatterns,
      predictedVulnerabilities,
      ...(astPatterns && { astPatterns }),
      // Store negative suppressors and exclude patterns on the definition
      // (extending the interface at runtime)
      ...(rule.negative_suppressors.length > 0 && { negativeSuppressors: rule.negative_suppressors }),
      ...(rule.exclude_patterns.length > 0 && { excludePatterns: rule.exclude_patterns }),
      ...(rule.min_patterns_required && { minPatternsRequired: rule.min_patterns_required }),
    } as VCVFPatternDefinition & {
      negativeSuppressors?: string[];
      excludePatterns?: string[];
      minPatternsRequired?: number;
    };
  }
}

/**
 * Create a RuleLoader instance.
 */
export function createRuleLoader(rulesDir?: string): RuleLoader {
  return new RuleLoader(rulesDir);
}

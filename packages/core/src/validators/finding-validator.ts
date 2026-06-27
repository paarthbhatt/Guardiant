import type { Finding, AppContext } from '@guardiant/shared';
import { createLogger } from '@guardiant/shared';
import { SUPPRESSION_RULES, type SuppressionRule } from './suppression-rules.js';

const logger = createLogger({ level: 'info' });

/**
 * Evidence quality assessment for a finding.
 */
interface EvidenceQuality {
  /** Has HTTP request/response data */
  hasRequestResponse: boolean;
  /** Has file path and line number */
  hasFileLocation: boolean;
  /** Has a meaningful code snippet (>20 chars) */
  hasSnippet: boolean;
  /** Has attack payload */
  hasPayload: boolean;
  /** Has concrete endpoint references */
  hasEndpoints: boolean;
  /** Only has VCVF pattern as context, no other evidence */
  onlyVcvfPattern: boolean;
  /** No evidence at all */
  noEvidence: boolean;
}

/**
 * Result of validating a single finding.
 */
export interface ValidationResult {
  /** The original finding (possibly with adjusted confidence) */
  finding: Finding;
  /** Whether the finding passed validation */
  passed: boolean;
  /** Reason for suppression (if not passed) */
  suppressedReason?: string;
  /** Rule ID that suppressed it */
  suppressedBy?: string;
  /** Original confidence before adjustment */
  originalConfidence: number;
  /** Adjusted confidence */
  adjustedConfidence: number;
}

/**
 * Finding Validator — gates every finding through a validation pipeline
 * before it enters the final report.
 *
 * Pipeline:
 *   Raw Finding
 *     → Suppression Check (known false positive patterns)
 *     → Evidence Quality Assessment
 *     → Dynamic Confidence Scoring
 *     → Validated Finding (or suppressed)
 */
export class FindingValidator {
  private rules: SuppressionRule[];

  constructor(rules: SuppressionRule[] = SUPPRESSION_RULES) {
    this.rules = rules;
  }

  /**
   * Validate a batch of findings, filtering out false positives
   * and adjusting confidence scores based on evidence quality.
   */
  validate(findings: Finding[], appContext?: AppContext): {
    validated: Finding[];
    suppressed: ValidationResult[];
    adjusted: ValidationResult[];
  } {
    const validated: Finding[] = [];
    const suppressed: ValidationResult[] = [];
    const adjusted: ValidationResult[] = [];

    for (const finding of findings) {
      const result = this.validateOne(finding, appContext);

      if (!result.passed) {
        suppressed.push(result);
        logger.info(`Suppressed finding: "${finding.title}" — ${result.suppressedReason}`);
      } else {
        // Apply adjusted confidence
        if (result.adjustedConfidence !== result.originalConfidence) {
          finding.confidence = result.adjustedConfidence;
          adjusted.push(result);
        }
        validated.push(finding);
      }
    }

    logger.info(
      `Validation complete: ${validated.length} passed, ${suppressed.length} suppressed, ` +
      `${adjusted.length} confidence-adjusted`
    );

    return { validated, suppressed, adjusted };
  }

  /**
   * Validate a single finding.
   */
  validateOne(finding: Finding, appContext?: AppContext): ValidationResult {
    const originalConfidence = finding.confidence;

    // Step 1: Check suppression rules
    for (const rule of this.rules) {
      if (rule.matches(finding, appContext)) {
        return {
          finding,
          passed: false,
          suppressedReason: rule.description,
          suppressedBy: rule.id,
          originalConfidence,
          adjustedConfidence: 0,
        };
      }
    }

    // Step 2: Assess evidence quality
    const evidenceQuality = this.assessEvidence(finding);

    // Step 3: Dynamic confidence scoring
    const adjustedConfidence = this.calculateDynamicConfidence(
      originalConfidence,
      evidenceQuality
    );

    return {
      finding,
      passed: true,
      originalConfidence,
      adjustedConfidence,
    };
  }

  /**
   * Assess the quality of evidence in a finding.
   */
  private assessEvidence(finding: Finding): EvidenceQuality {
    const ev = finding.evidence;

    const hasRequestResponse = Boolean(ev.request || ev.response);
    const hasFileLocation = Boolean(ev.file && ev.line);
    const hasSnippet = Boolean(ev.snippet && ev.snippet.length > 20);
    const hasPayload = Boolean(ev.payload);
    const hasEndpoints = Boolean(ev.endpoints && ev.endpoints.length > 0);

    // Detect VCVF-only evidence: only has a pattern name in context
    let onlyVcvfPattern = false;
    if (ev.context && typeof ev.context === 'object') {
      const ctx = ev.context as Record<string, unknown>;
      if (ctx.pattern && typeof ctx.pattern === 'string') {
        onlyVcvfPattern = !hasRequestResponse && !hasFileLocation && !hasSnippet && !hasPayload && !hasEndpoints;
      }
    }

    const noEvidence = !hasRequestResponse && !hasFileLocation && !hasSnippet && !hasPayload && !hasEndpoints && !onlyVcvfPattern;

    return {
      hasRequestResponse,
      hasFileLocation,
      hasSnippet,
      hasPayload,
      hasEndpoints,
      onlyVcvfPattern,
      noEvidence,
    };
  }

  /**
   * Calculate dynamic confidence based on evidence quality.
   *
   * This replaces the hardcoded 0.65-0.85 confidence values
   * that agents currently use regardless of evidence.
   */
  private calculateDynamicConfidence(base: number, evidence: EvidenceQuality): number {
    let confidence = base;

    // Boost for strong evidence
    if (evidence.hasRequestResponse) {
      confidence = Math.min(1, confidence + 0.15);
    }
    if (evidence.hasFileLocation) {
      confidence = Math.min(1, confidence + 0.1);
    }
    if (evidence.hasPayload) {
      confidence = Math.min(1, confidence + 0.1);
    }
    if (evidence.hasSnippet) {
      confidence = Math.min(1, confidence + 0.05);
    }

    // Penalize for weak evidence
    if (evidence.onlyVcvfPattern) {
      confidence = Math.min(confidence, 0.4);
    }
    if (evidence.noEvidence) {
      confidence = Math.min(confidence, 0.3);
    }

    return Math.round(confidence * 100) / 100;
  }
}

/**
 * Create a FindingValidator instance.
 */
export function createFindingValidator(rules?: SuppressionRule[]): FindingValidator {
  return new FindingValidator(rules);
}

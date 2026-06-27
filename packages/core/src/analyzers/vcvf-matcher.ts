import type { VCVFFingerprint, VCVFPatternType, Finding } from '@guardiant/shared';
import { VCVF_PATTERNS, type VCVFPatternDefinition } from '@guardiant/shared';
import { ASTParser } from './ast-parser.js';
import { TaintTracker } from './taint-tracker.js';

/**
 * VCVF (Vibe Code Vulnerability Fingerprint) Matcher
 *
 * Detects patterns unique to AI-generated code that indicate
 * higher likelihood of security vulnerabilities.
 *
 * Supports:
 * - Injected patterns from YAML rule loader
 * - Negative suppressors (skip pattern if suppressor found in same file)
 * - Exclude patterns (skip files matching exclude globs)
 */
export class VCVFMatcher {
  private patterns: VCVFPatternDefinition[];
  private negativeSuppressors: Map<string, string[]>;
  private excludePatterns: Map<string, string[]>;
  private minPatternsRequired: Map<string, number>;

  constructor(patterns?: VCVFPatternDefinition[]) {
    this.patterns = patterns ?? VCVF_PATTERNS;
    this.negativeSuppressors = new Map();
    this.excludePatterns = new Map();
    this.minPatternsRequired = new Map();

    // Extract runtime-only properties from extended definitions
    for (const p of this.patterns) {
      const ext = p as VCVFPatternDefinition & {
        negativeSuppressors?: string[];
        excludePatterns?: string[];
        minPatternsRequired?: number;
      };
      if (ext.negativeSuppressors) {
        this.negativeSuppressors.set(p.type, ext.negativeSuppressors);
      }
      if (ext.excludePatterns) {
        this.excludePatterns.set(p.type, ext.excludePatterns);
      }
      if (ext.minPatternsRequired) {
        this.minPatternsRequired.set(p.type, ext.minPatternsRequired);
      }
    }
  }

  /**
   * Analyze code for VCVF patterns
   */
  async analyze(code: string, filePath: string): Promise<VCVFFingerprint[]> {
    const fingerprints: VCVFFingerprint[] = [];
    
    // Instantiate ASTParser once per file
    const astParser = new ASTParser(code);

    for (const pattern of this.patterns) {
      const match = this.matchPattern(pattern, code, filePath, astParser);
      if (match) {
        fingerprints.push(match);
      }
    }

    return fingerprints;
  }

  /**
   * Match a single pattern
   */
  private matchPattern(
    pattern: VCVFPatternDefinition,
    code: string,
    filePath: string,
    astParser: ASTParser
  ): VCVFFingerprint | null {
    const taintTracker = new TaintTracker(code);
    // Check exclude patterns — skip files matching any exclude glob
    const excludes = this.excludePatterns.get(pattern.type) ?? [];
    for (const excludeGlob of excludes) {
      if (this.fileMatchesGlob(filePath, excludeGlob)) {
        return null;
      }
    }

    // Check file pattern first
    const fileMatches = pattern.filePatterns.some(fp => this.fileMatchesGlob(filePath, fp));

    if (!fileMatches && pattern.filePatterns.length > 0) {
      return null;
    }

    // Check negative suppressors — if any suppressor keyword is found in the
    // same file, skip this pattern match entirely
    const suppressors = this.negativeSuppressors.get(pattern.type) ?? [];
    if (suppressors.length > 0 && this.hasNegativeSuppressor(code, suppressors)) {
      return null;
    }

    // Check code patterns
    const matches: string[] = [];
    const locations: VCVFFingerprint['locations'] = [];

    for (const codePattern of pattern.codePatterns) {
      const patternRegex = typeof codePattern.pattern === 'string'
        ? new RegExp(codePattern.pattern, 'g')
        : codePattern.pattern;

      const found = code.match(patternRegex);
      if (found) {
        matches.push(codePattern.description);

        // Extract locations
        let match;
        const globalRegex = typeof codePattern.pattern === 'string'
          ? new RegExp(codePattern.pattern, 'g')
          : codePattern.pattern;

        while ((match = globalRegex.exec(code)) !== null) {
          const line = this.getLineNumber(code, match.index);
          locations.push({
            file: filePath,
            line,
            snippet: match[0].substring(0, 100),
          });
        }
      }
    }

    // Check AST patterns
    if (pattern.astPatterns && pattern.astPatterns.length > 0 && astParser.isParsable()) {
      for (const astPattern of pattern.astPatterns) {
        let astMatches: any[] = [];
        
        if (astPattern.nodeType === 'MethodCall' && astPattern.methodNames) {
          astMatches = astParser.findMethodCalls(astPattern.objectNames || [], astPattern.methodNames);
        } else {
          astMatches = astParser.findNodesByType(astPattern.nodeType);
        }

        if (astMatches.length > 0) {
          matches.push(astPattern.description);
          for (const match of astMatches) {
            locations.push({
              file: filePath,
              line: match.loc?.start?.line || this.getLineNumber(code, match.start),
              snippet: match.code.substring(0, 100),
            });
          }
        }
      }
    }

    // Check Taint patterns
    if (pattern.taintPatterns && pattern.taintPatterns.length > 0) {
      for (const taintPattern of pattern.taintPatterns) {
        const flows = taintTracker.analyzeFlows(
          taintPattern.sources,
          taintPattern.sinks,
          taintPattern.sanitizers || []
        );

        if (flows.length > 0) {
          // If we find an unsanitized flow, it's a strong match
          const hasVulnerability = flows.some(f => !f.isSanitized);
          if (hasVulnerability) {
            matches.push(taintPattern.description);
            for (const flow of flows) {
              if (!flow.isSanitized) {
                locations.push({
                  file: filePath,
                  line: flow.sinkLoc?.start?.line || 0,
                  snippet: `Flow from ${flow.sourceCode} to ${flow.sinkCode}`,
                });
              }
            }
          }
        }
      }
    }

    if (matches.length === 0) {
      return null;
    }

    // Enforce minimum patterns required (from YAML config)
    const minRequired = this.minPatternsRequired.get(pattern.type);
    if (minRequired && matches.length < minRequired) {
      return null;
    }

    // Calculate confidence
    const totalPatterns = pattern.codePatterns.length + (pattern.astPatterns?.length || 0) + (pattern.taintPatterns?.length || 0);
    const confidence = totalPatterns > 0 ? pattern.confidence * (matches.length / totalPatterns) : 0;

    // Generate predicted vulnerabilities
    const predictedVulnerabilities = pattern.predictedVulnerabilities.map(v => ({
      type: v.type,
      probability: v.probability * confidence,
      location: filePath,
      reason: v.reason,
    }));

    return {
      id: `vcvf_${pattern.type}_${Date.now()}`,
      patternType: pattern.type,
      confidence,
      evidence: matches,
      locations,
      predictedVulnerabilities,
    };
  }

  /**
   * Get line number from character index
   */
  private getLineNumber(code: string, index: number): number {
    const lines = code.substring(0, index).split('\n');
    return lines.length;
  }

  /**
   * Get all VCVF patterns
   */
  getPatterns(): VCVFPatternDefinition[] {
    return this.patterns;
  }

  /**
   * Get patterns by OWASP category
   */
  getPatternsByOWASP(owaspCategory: string): VCVFPatternDefinition[] {
    return this.patterns.filter(pattern =>
      pattern.predictedVulnerabilities.some(v => v.owaspCategory === owaspCategory)
    );
  }

  /**
   * Calculate composite VCVF score
   */
  calculateCompositeScore(fingerprints: VCVFFingerprint[]): number {
    if (fingerprints.length === 0) return 0;

    // Weight by confidence
    const totalConfidence = fingerprints.reduce((sum, f) => sum + f.confidence, 0);

    // Normalize to 0-10 scale
    return Math.min(10, (totalConfidence / fingerprints.length) * 10);
  }

  /**
   * Get pattern definition by type
   */
  getPatternByType(type: VCVFPatternType): VCVFPatternDefinition | undefined {
    return this.patterns.find(p => p.type === type);
  }

  /**
   * Predict missing vulnerabilities based on VCVF patterns
   */
  predictMissingVulnerabilities(fingerprints: VCVFFingerprint[]): Array<{
    type: string;
    probability: number;
    location: string;
    reason: string;
  }> {
    const predictions: Array<{
      type: string;
      probability: number;
      location: string;
      reason: string;
    }> = [];

    for (const fingerprint of fingerprints) {
      for (const prediction of fingerprint.predictedVulnerabilities) {
        // Check if this prediction already exists
        const existing = predictions.find(p => p.type === prediction.type);
        if (existing) {
          // Update probability (take max)
          existing.probability = Math.max(existing.probability, prediction.probability);
        } else {
          predictions.push({
            type: prediction.type,
            probability: prediction.probability,
            location: prediction.location,
            reason: prediction.reason,
          });
        }
      }
    }

    // Sort by probability descending
    predictions.sort((a, b) => b.probability - a.probability);

    return predictions;
  }

  /**
   * Check if findings correlate with VCVF patterns
   */
  correlateFindingsWithPatterns(findings: Finding[], fingerprints: VCVFFingerprint[]): {
    correlated: Finding[];
    uncorrelated: Finding[];
    predictions: Array<{ type: string; found: boolean }>;
  } {
    const correlated: Finding[] = [];
    const uncorrelated: Finding[] = [];

    for (const finding of findings) {
      const hasPattern = fingerprints.some(f =>
        finding.vcvfPattern === f.patternType ||
        f.predictedVulnerabilities.some(p => p.type === finding.category)
      );

      if (hasPattern) {
        correlated.push(finding);
      } else {
        uncorrelated.push(finding);
      }
    }

    // Check which predictions were found
    const predictions = fingerprints.flatMap(f => f.predictedVulnerabilities);
    const predictionResults = predictions.map(p => ({
      type: p.type,
      found: findings.some(f => f.category === p.type || f.tags.includes(p.type)),
    }));

    return { correlated, uncorrelated, predictions: predictionResults };
  }

  /**
   * Check if code contains any negative suppressor keywords.
   * If found, the pattern match should be skipped for this file.
   */
  private hasNegativeSuppressor(code: string, suppressors: string[]): boolean {
    for (const suppressor of suppressors) {
      if (code.includes(suppressor)) return true;
    }
    return false;
  }

  /**
   * Check if a file path matches a glob pattern.
   */
  private fileMatchesGlob(filePath: string, glob: string): boolean {
    let regexPattern = glob
      .replace(/\*\*\//g, '___GLOBSTAR___')
      .replace(/\*/g, '___STAR___')
      .replace(/\./g, '\\.')
      .replace(/\{([^}]+)\}/g, (_, alternatives: string) => `(${alternatives.replace(/,/g, '|')})`)
      .replace(/___GLOBSTAR___/g, '(?:.*/)?')
      .replace(/___STAR___/g, '[^/]*');
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(filePath);
  }
}

/**
 * Create VCVF matcher with optional injected patterns
 */
export function createVCVFMatcher(patterns?: VCVFPatternDefinition[]): VCVFMatcher {
  return new VCVFMatcher(patterns);
}
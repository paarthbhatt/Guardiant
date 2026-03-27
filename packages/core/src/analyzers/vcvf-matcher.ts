import type { VCVFFingerprint, VCVFPatternType, Finding } from '@guardiant/shared';
import { VCVF_PATTERNS, type VCVFPatternDefinition } from '@guardiant/shared';

/**
 * VCVF (Vibe Code Vulnerability Fingerprint) Matcher
 *
 * Detects patterns unique to AI-generated code that indicate
 * higher likelihood of security vulnerabilities.
 */
export class VCVFMatcher {
  private patterns: VCVFPatternDefinition[];

  constructor() {
    this.patterns = VCVF_PATTERNS;
  }

  /**
   * Analyze code for VCVF patterns
   */
  async analyze(code: string, filePath: string): Promise<VCVFFingerprint[]> {
    const fingerprints: VCVFFingerprint[] = [];

    for (const pattern of this.patterns) {
      const match = this.matchPattern(pattern, code, filePath);
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
    filePath: string
  ): VCVFFingerprint | null {
    // Check file pattern first
    const fileMatches = pattern.filePatterns.some(fp => {
      // Convert glob pattern to regex
      // Handle **/ as a unit to properly match zero or more directories
      let regexPattern = fp
        .replace(/\*\*\//g, '___GLOBSTAR___') // Replace **/ as a unit first
        .replace(/\*/g, '___STAR___')         // Replace remaining * 
        .replace(/\./g, '\\.')                 // Escape literal dots
        .replace(/\{([^}]+)\}/g, (_, alternatives) => `(${alternatives.replace(/,/g, '|')})`) // Brace expansion
        .replace(/___GLOBSTAR___/g, '(?:.*/)?') // **/ becomes optional "anything ending in slash"
        .replace(/___STAR___/g, '[^/]*');       // * becomes "zero or more non-slash"
      
      const regex = new RegExp(`^${regexPattern}$`);
      return regex.test(filePath);
    });

    if (!fileMatches && pattern.filePatterns.length > 0) {
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

    if (matches.length === 0) {
      return null;
    }

    // Calculate confidence
    const confidence = pattern.confidence * (matches.length / pattern.codePatterns.length);

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
}

/**
 * Create VCVF matcher
 */
export function createVCVFMatcher(): VCVFMatcher {
  return new VCVFMatcher();
}
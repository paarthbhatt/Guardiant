import type { Finding, VulnerabilityEvidence, Remediation, Severity, OWASPCategory } from '@guardiant/shared';
import { generateFindingId, cvssToSeverity } from '@guardiant/shared';

/**
 * Agent-specific types
 */

/**
 * Test result from an agent
 */
export interface AgentTestResult {
  /** Test name */
  name: string;
  /** Test passed */
  passed: boolean;
  /** Evidence collected */
  evidence: VulnerabilityEvidence;
  /** Error if failed */
  error?: string;
  /** Duration in ms */
  duration: number;
}

/**
 * Finding builder for easier construction
 */
export class FindingBuilder {
  private finding: Partial<Finding> = {};

  constructor(private agentId: string) {}

  title(title: string): this {
    this.finding.title = title;
    return this;
  }

  description(description: string): this {
    this.finding.description = description;
    return this;
  }

  severity(severity: Severity): this {
    this.finding.severity = severity;
    return this;
  }

  cvssScore(score: number): this {
    this.finding.cvssScore = score;
    this.finding.severity = cvssToSeverity(score);
    return this;
  }

  category(category: OWASPCategory): this {
    this.finding.category = category;
    return this;
  }

  confidence(confidence: number): this {
    this.finding.confidence = Math.max(0, Math.min(1, confidence));
    return this;
  }

  evidence(evidence: VulnerabilityEvidence): this {
    this.finding.evidence = evidence;
    return this;
  }

  remediation(remediation: Remediation): this {
    this.finding.remediation = remediation;
    return this;
  }

  tags(tags: string[]): this {
    this.finding.tags = tags;
    return this;
  }

  addTag(tag: string): this {
    if (!this.finding.tags) {
      this.finding.tags = [];
    }
    this.finding.tags.push(tag);
    return this;
  }

  cvcChain(chainId: string): this {
    this.finding.cvcChainId = chainId;
    return this;
  }

  vcvfPattern(pattern: string): this {
    this.finding.vcvfPattern = pattern;
    return this;
  }

  tiefIndicator(indicator: string): this {
    this.finding.tiefIndicator = indicator;
    return this;
  }

  build(): Finding {
    if (!this.finding.title || !this.finding.description) {
      throw new Error('Finding must have title and description');
    }

    if (!this.finding.category) {
      throw new Error('Finding must have category');
    }

    return {
      id: generateFindingId(this.agentId, this.finding.category),
      title: this.finding.title,
      description: this.finding.description,
      severity: this.finding.severity ?? 'medium',
      category: this.finding.category,
      cvssScore: this.finding.cvssScore ?? 5.0,
      confidence: this.finding.confidence ?? 0.8,
      discoveredBy: this.agentId,
      timestamp: new Date().toISOString(),
      evidence: this.finding.evidence ?? {},
      remediation: this.finding.remediation ?? {
        summary: 'Remediation required',
        steps: ['Investigate and fix the vulnerability'],
        effort: 'medium',
        priority: 5,
      },
      status: 'open',
      tags: this.finding.tags ?? [],
      cvcChainId: this.finding.cvcChainId,
      vcvfPattern: this.finding.vcvfPattern,
      tiefIndicator: this.finding.tiefIndicator,
    };
  }
}

/**
 * Create a finding builder
 */
export function createFinding(agentId: string): FindingBuilder {
  return new FindingBuilder(agentId);
}

/**
 * Test case for security agents
 */
export interface SecurityTest {
  /** Test ID */
  id: string;
  /** Test name */
  name: string;
  /** Test description */
  description: string;
  /** OWASP category */
  category: OWASPCategory;
  /** Expected severity if found */
  severity: Severity;
  /** Test payload */
  payload?: string;
  /** Success condition */
  successCondition: (response: string, status: number) => boolean;
  /** Evidence extraction */
  extractEvidence?: (response: string, request: string) => VulnerabilityEvidence;
}

/**
 * HTTP request options for agents
 */
export interface AgentRequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeout?: number;
  followRedirects?: boolean;
}

/**
 * HTTP response for agents
 */
export interface AgentResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  duration: number;
}
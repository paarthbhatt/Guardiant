import type { Finding, VulnerabilityChain, DataFlow } from '@guardiant/shared';

/**
 * CVC (Compound Vulnerability Chain) Analyzer
 *
 * Links related vulnerabilities into exploit chains where
 * V1 enables exploitation of V2, resulting in compound impact.
 */
export class CVCAnalyzer {
  /**
   * Find compound vulnerability chains
   */
  async findChains(findings: Finding[], _dataFlows?: DataFlow[]): Promise<VulnerabilityChain[]> {
    if (findings.length < 2) {
      return [];
    }

    const chains: VulnerabilityChain[] = [];

    // Build adjacency list of chainable vulnerabilities
    const adjacency = this.buildAdjacencyList(findings);

    // Find all chains (paths in the graph)
    const visited = new Set<string>();
    for (const finding of findings) {
      if (!visited.has(finding.id)) {
        const chain = this.findChainFrom(finding, adjacency, visited);
        if (chain.length >= 2) {
          chains.push(this.createChain(chain));
        }
      }
    }

    // Sort by compound severity
    chains.sort((a, b) => {
      const severities = ['critical', 'high', 'medium', 'low', 'info'];
      return severities.indexOf(a.compoundSeverity) - severities.indexOf(b.compoundSeverity);
    });

    return chains;
  }

  /**
   * Build adjacency list of chainable vulnerability pairs
   */
  private buildAdjacencyList(findings: Finding[]): Map<string, Finding[]> {
    const adjacency = new Map<string, Finding[]>();

    for (const v1 of findings) {
      for (const v2 of findings) {
        if (v1.id === v2.id) continue;

        if (this.canChain(v1, v2)) {
          const neighbors = adjacency.get(v1.id) ?? [];
          neighbors.push(v2);
          adjacency.set(v1.id, neighbors);
        }
      }
    }

    return adjacency;
  }

  /**
   * Check if vulnerability V1 can enable exploitation of V2
   */
  private canChain(v1: Finding, v2: Finding): boolean {
    // Chainable category pairs
    const chainablePairs: Array<[string, string, string]> = [
      // (V1 category, V2 category, reason)
      ['A01_BROKEN_ACCESS_CONTROL', 'A03_INJECTION', 'IDOR reveals injection points'],
      ['A05_SECURITY_MISCONFIGURATION', 'A01_BROKEN_ACCESS_CONTROL', 'Config leaks enable access'],
      ['A02_CRYPTOGRAPHIC_FAILURES', 'A07_AUTH_FAILURES', 'Secret exposure enables auth bypass'],
      ['A03_INJECTION', 'A01_BROKEN_ACCESS_CONTROL', 'SQLi reveals access patterns'],
      ['A07_AUTH_FAILURES', 'A01_BROKEN_ACCESS_CONTROL', 'Auth bypass enables IDOR'],
      ['A05_SECURITY_MISCONFIGURATION', 'A02_CRYPTOGRAPHIC_FAILURES', 'Debug mode exposes secrets'],
      ['A01_BROKEN_ACCESS_CONTROL', 'A02_CRYPTOGRAPHIC_FAILURES', 'IDOR exposes credentials'],
      ['A05_SECURITY_MISCONFIGURATION', 'A03_INJECTION', 'CORS misconfig enables injection'],
    ];

    // Check if this pair is chainable
    const isChainable = chainablePairs.some(
      ([cat1, cat2]) => v1.category === cat1 && v2.category === cat2
    );

    if (!isChainable) return false;

    // Check if V1 and V2 share data flow (if available)
    // In a real implementation, we'd check if V1's output can reach V2's input

    // Check severity relationship - V1 should enable V2
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const v1Severity = severityOrder.indexOf(v1.severity);
    const v2Severity = severityOrder.indexOf(v2.severity);

    // Chains are more interesting when compound impact is higher
    return v1Severity <= v2Severity + 1; // Allow some severity difference
  }

  /**
   * Find a chain starting from a vulnerability
   */
  private findChainFrom(
    start: Finding,
    adjacency: Map<string, Finding[]>,
    visited: Set<string>
  ): Finding[] {
    const chain: Finding[] = [];
    const queue: Finding[] = [start];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current.id)) continue;

      visited.add(current.id);
      chain.push(current);

      const neighbors = adjacency.get(current.id) ?? [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor.id)) {
          queue.push(neighbor);
        }
      }
    }

    return chain;
  }

  /**
   * Create a VulnerabilityChain from findings
   */
  private createChain(findings: Finding[]): VulnerabilityChain {
    const compoundSeverity = this.calculateCompoundSeverity(findings);
    const compoundCvss = this.calculateCompoundCvss(findings);
    const exploitPath = this.generateExploitPath(findings);
    const attackSteps = this.generateAttackSteps(findings);

    return {
      id: `chain_${findings.map(f => f.id).join('_')}`,
      findings,
      compoundSeverity,
      compoundCvssScore: compoundCvss,
      exploitPath,
      attackSteps,
    };
  }

  /**
   * Calculate compound severity
   */
  private calculateCompoundSeverity(findings: Finding[]): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

    // Compound severity is at least as severe as the worst finding
    let worstSeverity = 'info';
    for (const finding of findings) {
      if (severityOrder.indexOf(finding.severity) < severityOrder.indexOf(worstSeverity)) {
        worstSeverity = finding.severity;
      }
    }

    // Chains of 3+ high/critical findings compound to critical
    const highCriticalCount = findings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    ).length;

    if (highCriticalCount >= 3) {
      return 'critical';
    }

    // Chains of 2 high findings compound to critical
    if (highCriticalCount === 2 && findings.length >= 2) {
      return (worstSeverity === 'high' ? 'critical' : worstSeverity) as 'critical' | 'high' | 'medium' | 'low' | 'info';
    }

    return worstSeverity as 'critical' | 'high' | 'medium' | 'low' | 'info';
  }

  /**
   * Calculate compound CVSS score
   */
  private calculateCompoundCvss(findings: Finding[]): number {
    // Compound CVSS is based on the chain, not just individual scores
    const baseScores = findings.map(f => f.cvssScore);

    // Take the highest score and add contribution from others
    const maxScore = Math.max(...baseScores);
    const otherScores = baseScores.filter(s => s < maxScore);

    // Each additional vulnerability adds some compound impact
    const compoundContribution = otherScores.reduce((sum, score) => sum + score * 0.1, 0);

    return Math.min(10, maxScore + compoundContribution);
  }

  /**
   * Generate exploit path description
   */
  private generateExploitPath(findings: Finding[]): string {
    if (findings.length === 0) return '';

    const steps = findings.map((f, i) => `${i + 1}. Exploit ${f.title}`);
    return `Attack chain:\n${steps.join('\n')}\n\nCompound impact: Multiple vulnerabilities chained to achieve greater impact than individual vulnerabilities.`;
  }

  /**
   * Generate attack steps for the chain
   */
  private generateAttackSteps(findings: Finding[]): VulnerabilityChain['attackSteps'] {
    return findings.map((finding, index) => ({
      order: index + 1,
      findingId: finding.id,
      action: `Exploit ${finding.title}`,
      result: index < findings.length - 1
        ? `Enables exploitation of ${findings[index + 1]?.title ?? 'next vulnerability'}`
        : `Achieves compound impact: ${finding.severity} severity`,
    }));
  }

  /**
   * Calculate severity for a specific finding in the context of a chain
   */
  calculateChainAdjustedSeverity(finding: Finding, chain: VulnerabilityChain): number {
    // Findings in a chain have higher impact
    const chainMultiplier = chain.findings.length > 2 ? 1.2 : 1.1;
    return Math.min(10, finding.cvssScore * chainMultiplier);
  }
  /**
   * Alias for findChains — used by integration tests and external callers
   */
  async analyze(findings: Finding[], dataFlows?: DataFlow[]): Promise<VulnerabilityChain[]> {
    return this.findChains(findings, dataFlows);
  }
}

/**
 * Create CVC analyzer
 */
export function createCVCAnalyzer(): CVCAnalyzer {
  return new CVCAnalyzer();
}
/**
 * Chain-of-thought reasoning helpers for LLM interactions
 */

import type { LLMClient } from './client.js';
import type { Finding, VulnerabilityChain, TrustInversion } from '@guardiant/shared';

/**
 * Reasoning step for chain-of-thought
 */
export interface ReasoningStep {
  step: number;
  type: 'observation' | 'hypothesis' | 'test' | 'conclusion';
  description: string;
  finding?: string;
  confidence?: number;
}

/**
 * Build a chain-of-thought prompt
 */
export function buildReasoningPrompt(
  task: string,
  context: string,
  previousSteps: ReasoningStep[] = []
): string {
  const stepsText = previousSteps.length > 0
    ? `\n\nPrevious reasoning steps:\n${previousSteps.map(s =>
        `${s.step}. [${s.type.toUpperCase()}] ${s.description}${s.finding ? ` → Finding: ${s.finding}` : ''}`
      ).join('\n')}`
    : '';

  return `You are performing a security analysis task.

Task: ${task}

Context:
${context}
${stepsText}

Think through this step by step:
1. First, observe what you can see
2. Form hypotheses about potential vulnerabilities
3. Consider how to test each hypothesis
4. Draw conclusions based on evidence

For each step, indicate:
- The type (observation, hypothesis, test, conclusion)
- Your reasoning
- Confidence level (0-1)
- Any findings

Provide your analysis in a structured format.`;
}

/**
 * Perform iterative reasoning with the LLM
 */
export async function iterativeReasoning(
  llm: LLMClient,
  task: string,
  context: string,
  maxIterations: number = 5
): Promise<{ steps: ReasoningStep[]; conclusion: string }> {
  const steps: ReasoningStep[] = [];

  for (let i = 0; i < maxIterations; i++) {
    const prompt = buildReasoningPrompt(task, context, steps);

    // In a real implementation, this would call the LLM
    // For now, return placeholder

    // Add step if we got one
    // steps.push(newStep);

    // Check if we've reached a conclusion
    // if (newStep.type === 'conclusion') break;
  }

  return {
    steps,
    conclusion: 'Analysis complete',
  };
}

/**
 * Find compound vulnerability chains (CVC)
 */
export async function findCVCChains(
  llm: LLMClient,
  findings: Finding[]
): Promise<VulnerabilityChain[]> {
  if (findings.length < 2) {
    return [];
  }

  // Group findings by data flow
  // Look for chains where V1 enables V2

  const chains: VulnerabilityChain[] = [];

  // For each pair of vulnerabilities, check if they can be chained
  for (let i = 0; i < findings.length; i++) {
    for (let j = 0; j < findings.length; j++) {
      if (i === j) continue;

      const canChain = await canChainVulnerabilities(llm, findings[i], findings[j]);
      if (canChain) {
        chains.push({
          id: `chain_${findings[i].id}_${findings[j].id}`,
          findings: [findings[i], findings[j]],
          compoundSeverity: getCompoundSeverity(findings[i].severity, findings[j].severity),
          compoundCvssScore: Math.min(findings[i].cvssScore + findings[j].cvssScore * 0.5, 10),
          exploitPath: `Exploit ${findings[i].title} to enable ${findings[j].title}`,
          attackSteps: [
            { order: 1, findingId: findings[i].id, action: 'Exploit first vulnerability', result: 'Gain initial access' },
            { order: 2, findingId: findings[j].id, action: 'Exploit second vulnerability', result: 'Achieve compound impact' },
          ],
        });
      }
    }
  }

  return chains;
}

/**
 * Check if two vulnerabilities can be chained
 */
async function canChainVulnerabilities(
  llm: LLMClient,
  v1: Finding,
  v2: Finding
): Promise<boolean> {
  // Heuristic: Check if V1's impact enables V2's exploitation
  // For example:
  // - IDOR + XSS can chain
  // - SQLi + Auth bypass can chain
  // - Secret exposure + API access can chain

  const chainablePairs: Array<[string, string]> = [
    ['A01_BROKEN_ACCESS_CONTROL', 'A03_INJECTION'], // IDOR enables SQLi vectors
    ['A05_SECURITY_MISCONFIGURATION', 'A01_BROKEN_ACCESS_CONTROL'], // Config exposure reveals access patterns
    ['A02_CRYPTOGRAPHIC_FAILURES', 'A07_AUTH_FAILURES'], // Secret exposure enables auth bypass
    ['A03_INJECTION', 'A01_BROKEN_ACCESS_CONTROL'], // SQLi enables privilege escalation
    ['A07_AUTH_FAILURES', 'A01_BROKEN_ACCESS_CONTROL'], // Auth bypass enables IDOR
  ];

  return chainablePairs.some(
    ([cat1, cat2]) => v1.category === cat1 && v2.category === cat2
  );
}

/**
 * Calculate compound severity
 */
function getCompoundSeverity(s1: string, s2: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const i1 = severities.indexOf(s1);
  const i2 = severities.indexOf(s2);

  // Compound is at least as severe as the more severe one
  return severities[Math.min(i1, i2)] as 'critical' | 'high' | 'medium' | 'low' | 'info';
}

/**
 * Detect TIEF (Trust Inversion Exploit Framework)
 */
export async function detectTIEF(
  llm: LLMClient,
  findings: Finding[],
  chains: VulnerabilityChain[]
): Promise<TrustInversion[]> {
  const inversions: TrustInversion[] = [];

  // Look for trust inversion patterns
  const trustInversionPatterns = [
    {
      type: 'frontend_auth_logic',
      indicators: ['auth_authz_conflation', 'optimistic_trust_patterns'],
      description: 'Authentication logic implemented on frontend only',
    },
    {
      type: 'direct_database_access',
      indicators: ['baas_bypass_architecture'],
      description: 'Client has direct database access without server validation',
    },
    {
      type: 'client_secrets',
      indicators: ['baas_bypass_architecture', 'over_permissive_defaults'],
      description: 'Secrets or API keys stored in client-side code',
    },
  ];

  // Check findings for VCVF patterns indicating trust inversions
  for (const pattern of trustInversionPatterns) {
    const matchingFindings = findings.filter(f =>
      f.vcvfPattern && pattern.indicators.includes(f.vcvfPattern)
    );

    if (matchingFindings.length > 0) {
      inversions.push({
        id: `tief_${pattern.type}_${Date.now()}`,
        type: pattern.type as TrustInversion['type'],
        misplacedTrust: 'Client-side code',
        expectedBoundary: 'Server-side validation and authorization',
        actualBoundary: 'Client-side only checks',
        severity: matchingFindings[0].severity,
        findingIds: matchingFindings.map(f => f.id),
      });
    }
  }

  return inversions;
}
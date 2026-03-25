import type { Finding, TrustInversion } from '@guardiant/shared';

/**
 * TIEF (Trust Inversion Exploit Framework) Detector
 *
 * Identifies where trust boundaries are misconfigured in
 * AI-generated applications.
 */
export class TIEFDetector {
  /**
   * Trust inversion patterns
   */
  private readonly inversionPatterns: Array<{
    type: TrustInversion['type'];
    indicators: string[];
    description: string;
    misplacedTrust: string;
    expectedBoundary: string;
    actualBoundary: string;
  }> = [
    {
      type: 'frontend_auth_logic',
      indicators: ['auth_authz_conflation', 'optimistic_trust_patterns', 'missing_negative_cases'],
      description: 'Authentication and authorization logic is implemented primarily on the frontend',
      misplacedTrust: 'Frontend JavaScript code',
      expectedBoundary: 'Backend server with proper authentication middleware',
      actualBoundary: 'Client-side JavaScript checks that can be bypassed',
    },
    {
      type: 'direct_database_access',
      indicators: ['baas_bypass_architecture', 'optimistic_trust_patterns'],
      description: 'Client application has direct database access without server-side validation',
      misplacedTrust: 'Client-side BaaS SDK (Supabase/Firebase)',
      expectedBoundary: 'Server-side API that validates and authorizes all requests',
      actualBoundary: 'Direct database queries from client without RLS policies',
    },
    {
      type: 'client_secrets',
      indicators: ['baas_bypass_architecture', 'over_permissive_defaults'],
      description: 'Sensitive secrets are stored in client-side code',
      misplacedTrust: 'Client-side environment variables or code',
      expectedBoundary: 'Server-side secrets management (env vars, vault)',
      actualBoundary: 'NEXT_PUBLIC_*, REACT_APP_*, or hardcoded secrets in bundles',
    },
    {
      type: 'missing_server_validation',
      indicators: ['optimistic_trust_patterns', 'missing_negative_cases'],
      description: 'Server-side validation is missing or minimal',
      misplacedTrust: 'Client-side form validation',
      expectedBoundary: 'Server-side validation for all inputs',
      actualBoundary: 'Assumption that client validation is sufficient',
    },
    {
      type: 'over_permissive_cors',
      indicators: ['over_permissive_defaults'],
      description: 'CORS configuration allows any origin',
      misplacedTrust: 'Any origin can make requests',
      expectedBoundary: 'CORS restricted to trusted origins',
      actualBoundary: 'Access-Control-Allow-Origin: *',
    },
    {
      type: 'insecure_defaults',
      indicators: ['over_permissive_defaults', 'baas_bypass_architecture'],
      description: 'Default configurations are insecure',
      misplacedTrust: 'Development defaults in production',
      expectedBoundary: 'Secure-by-default configuration',
      actualBoundary: 'Debug mode enabled, weak passwords, public access',
    },
  ];

  /**
   * Detect trust inversions from findings
   */
  async detect(findings: Finding[]): Promise<TrustInversion[]> {
    const inversions: TrustInversion[] = [];

    for (const pattern of this.inversionPatterns) {
      // Find findings that match this inversion pattern
      const matchingFindings = findings.filter(f =>
        f.vcvfPattern && pattern.indicators.includes(f.vcvfPattern)
      );

      if (matchingFindings.length > 0) {
        // Calculate severity based on findings
        const severity = this.calculateInversionSeverity(matchingFindings);

        inversions.push({
          id: `tief_${pattern.type}_${Date.now()}`,
          type: pattern.type,
          misplacedTrust: pattern.misplacedTrust,
          expectedBoundary: pattern.expectedBoundary,
          actualBoundary: pattern.actualBoundary,
          severity,
          findingIds: matchingFindings.map(f => f.id),
        });
      }
    }

    // Also check for implicit inversions (multiple low findings indicating a pattern)
    const implicitInversions = this.detectImplicitInversions(findings);
    inversions.push(...implicitInversions);

    // Sort by severity
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    inversions.sort((a, b) =>
      severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
    );

    return inversions;
  }

  /**
   * Calculate inversion severity from findings
   */
  private calculateInversionSeverity(findings: Finding[]): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

    // Inversion severity is the worst of its findings
    let worst = 'info';
    for (const finding of findings) {
      if (severityOrder.indexOf(finding.severity) < severityOrder.indexOf(worst)) {
        worst = finding.severity;
      }
    }

    // Trust inversions compound severity
    if (worst === 'critical' || worst === 'high') {
      return 'critical';
    }

    if (worst === 'medium' && findings.length >= 2) {
      return 'high';
    }

    return worst as 'critical' | 'high' | 'medium' | 'low' | 'info';
  }

  /**
   * Detect implicit inversions from patterns
   */
  private detectImplicitInversions(findings: Finding[]): TrustInversion[] {
    const inversions: TrustInversion[] = [];

    // Check for BaaS bypass architecture pattern
    const baasFindings = findings.filter(f =>
      f.category === 'A01_BROKEN_ACCESS_CONTROL' ||
      f.category === 'A05_SECURITY_MISCONFIGURATION'
    );

    if (baasFindings.length >= 3) {
      // Multiple access control issues suggest architecture problem
      inversions.push({
        id: `tief_implicit_baas_${Date.now()}`,
        type: 'direct_database_access',
        misplacedTrust: 'BaaS client SDK',
        expectedBoundary: 'Server-side API with authorization',
        actualBoundary: 'Client directly accessing database',
        severity: 'high',
        findingIds: baasFindings.map(f => f.id),
      });
    }

    // Check for auth/authz conflation
    const authFindings = findings.filter(f =>
      f.tags.includes('auth') ||
      f.tags.includes('authorization') ||
      f.tags.includes('idor')
    );

    if (authFindings.length >= 2) {
      inversions.push({
        id: `tief_implicit_auth_${Date.now()}`,
        type: 'frontend_auth_logic',
        misplacedTrust: 'Frontend auth checks',
        expectedBoundary: 'Backend authorization middleware',
        actualBoundary: 'Client-side role checks',
        severity: 'high',
        findingIds: authFindings.map(f => f.id),
      });
    }

    return inversions;
  }

  /**
   * Find the weakest trust anchor
   */
  findWeakestAnchor(inversions: TrustInversion[]): TrustInversion | null {
    if (inversions.length === 0) return null;

    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

    // Sort by severity and return the worst
    return inversions.sort((a, b) =>
      severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
    )[0];
  }

  /**
   * Generate attack path around trust inversion
   */
  generateAttackPath(inversion: TrustInversion, findings: Finding[]): string {
    const relatedFindings = findings.filter(f => inversion.findingIds.includes(f.id));

    const steps: string[] = [];

    steps.push(`## Trust Inversion Attack Path\n`);
    steps.push(`**Type:** ${inversion.type}`);
    steps.push(`**Misplaced Trust:** ${inversion.misplacedTrust}`);
    steps.push(`**Severity:** ${inversion.severity}\n`);

    steps.push(`### Vulnerabilities Exploited:`);
    for (const finding of relatedFindings) {
      steps.push(`- ${finding.title} (${finding.severity})`);
    }

    steps.push(`\n### Attack Steps:`);
    steps.push(`1. Identify that trust boundary is incorrectly placed at ${inversion.misplacedTrust}`);
    steps.push(`2. Bypass client-side checks by modifying client code or making direct API calls`);
    steps.push(`3. Exploit the gap between ${inversion.actualBoundary} and ${inversion.expectedBoundary}`);

    steps.push(`\n### Remediation:`);
    steps.push(`- Move trust boundary to ${inversion.expectedBoundary}`);
    steps.push(`- Implement server-side validation and authorization`);
    steps.push(`- Never trust client-side checks for security decisions`);

    return steps.join('\n');
  }

  /**
   * Get all inversion patterns
   */
  getPatterns(): typeof this.inversionPatterns {
    return this.inversionPatterns;
  }
}

/**
 * Create TIEF detector
 */
export function createTIEFDetector(): TIEFDetector {
  return new TIEFDetector();
}